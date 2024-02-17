// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::error::{ErrExcp, TdxError};
use super::gctx::{GuestCpuContext, GuestCpuGPRegCode};
use super::gmem::{accept_guest_mem, convert_guest_mem};
use super::ioreq::{IoDirection, IoReq, IoType};
use super::percpu::{this_vcpu, this_vcpu_mut};
use super::tdcall::{tdcall_get_td_info, tdvmcall_sti_halt};
use super::tdp::this_tdp;
use super::utils::{
    td_add_page_alias, GPAAttr, L2ExitInfo, TdCallLeaf, TdVmCallLeaf, TdpVmId,
    TDG_VP_VMCALL_INVALID_OPERAND, TDG_VP_VMCALL_RETRY, TDG_VP_VMCALL_SUCCESS, TDX_OPERAND_INVALID,
    TDX_SUCCESS,
};
use super::vcpu_comm::VcpuReqFlags;
use super::vmcs_lib::{VMX_INT_INFO_ERR_CODE_VALID, VMX_INT_INFO_VALID};
use crate::address::{Address, GuestPhysAddr};
use crate::cpu::control_regs::{write_xcr, CR4Flags, XCR0Flags, XCR0_RSVD};
use crate::cpu::features::cpu_has_xcr0_features;
use crate::cpu::idt::common::triple_fault;
use crate::cpu::interrupts::{disable_irq, enable_irq};
use crate::mm::address_space::is_kernel_phys_addr_valid;
use crate::mm::guestmem::{gpa_is_shared, gpa_strip_c_bit};
use crate::mm::memory::is_guest_phys_addr_valid;
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug)]
    pub struct EPTViolationQualFlags: u64 {
        const R     = 1 << 0;
        const W     = 1 << 1;
        const X     = 1 << 2;
        const RA    = 1 << 3;
        const WA    = 1 << 4;
        const XA    = 1 << 5;
        const GLA   = 1 << 7;
        const TRAN  = 1 << 8;
    }
}

#[derive(Copy, Clone, Debug)]
pub enum CrAccessType {
    MovToCr(u8, GuestCpuGPRegCode),
    MovFromCr(u8, GuestCpuGPRegCode),
    Clts,
    Lmsw,
}

#[derive(Copy, Clone, Debug)]
pub enum VmExitReason {
    ExceptionNMI {
        intr_info: u32,
        intr_errcode: u32,
    },
    ExternalInterrupt,
    TripleFault,
    InitSignal,
    InterruptWindow,
    Cpuid,
    Hlt,
    Vmcall {
        cpl: u8,
    },
    CrAccess {
        access_type: CrAccessType,
    },
    IoInstruction {
        size: usize,
        read: bool,
        string: bool,
        port: u16,
    },
    MsrRead,
    MsrWrite,
    TprBelowThreshold,
    EoiInduced {
        vec: u8,
    },
    EptViolation {
        fault_gpa: GuestPhysAddr,
        flags: EPTViolationQualFlags,
    },
    Wbinvd,
    Xsetbv {
        cpl: u8,
    },
    Tdcall,
    UnSupported(u32),
}

impl VmExitReason {
    fn new(l2exit_info: &L2ExitInfo) -> Self {
        let exit_reason = l2exit_info.exit_reason;
        match exit_reason {
            0 => VmExitReason::ExceptionNMI {
                intr_info: l2exit_info.exit_intr_info,
                intr_errcode: l2exit_info.exit_intr_errcode,
            },
            1 => VmExitReason::ExternalInterrupt,
            2 => VmExitReason::TripleFault,
            3 => VmExitReason::InitSignal,
            7 => VmExitReason::InterruptWindow,
            10 => VmExitReason::Cpuid,
            12 => VmExitReason::Hlt,
            18 => VmExitReason::Vmcall {
                cpl: l2exit_info.cpl,
            },
            28 => VmExitReason::CrAccess {
                access_type: {
                    let qualification = l2exit_info.exit_qual;
                    let cr_num = (qualification & 0xf) as u8;
                    let reg_idx = ((qualification >> 8) & 0xf) as u8;
                    match (qualification >> 4) & 0x3 {
                        0 => CrAccessType::MovToCr(
                            cr_num,
                            GuestCpuGPRegCode::try_from(reg_idx).unwrap(),
                        ),
                        1 => CrAccessType::MovFromCr(
                            cr_num,
                            GuestCpuGPRegCode::try_from(reg_idx).unwrap(),
                        ),
                        2 => CrAccessType::Clts,
                        3 => CrAccessType::Lmsw,
                        _ => unreachable!("VmExitCRInfo: invalid qualification"),
                    }
                },
            },
            30 => VmExitReason::IoInstruction {
                size: ((l2exit_info.exit_qual & 0x7) + 1) as usize,
                read: (l2exit_info.exit_qual & 0x8) != 0,
                string: (l2exit_info.exit_qual & 0x10) != 0,
                port: (l2exit_info.exit_qual >> 16) as u16,
            },
            31 => VmExitReason::MsrRead,
            32 => VmExitReason::MsrWrite,
            43 => VmExitReason::TprBelowThreshold,
            45 => VmExitReason::EoiInduced {
                vec: (l2exit_info.exit_qual & 0xff) as u8,
            },
            48 => VmExitReason::EptViolation {
                fault_gpa: GuestPhysAddr::from(l2exit_info.fault_gpa),
                flags: EPTViolationQualFlags::from_bits_truncate(l2exit_info.exit_qual),
            },
            54 => VmExitReason::Wbinvd,
            55 => VmExitReason::Xsetbv {
                cpl: l2exit_info.cpl,
            },
            77 => VmExitReason::Tdcall,
            _ => VmExitReason::UnSupported(exit_reason),
        }
    }
}

pub struct VmExit {
    vm_id: TdpVmId,
    exit_instr_len: u32,
    pub reason: VmExitReason,
}

impl VmExit {
    pub fn new(vm_id: TdpVmId, l2exit_info: L2ExitInfo) -> Self {
        let reason = VmExitReason::new(&l2exit_info);
        VmExit {
            vm_id,
            exit_instr_len: l2exit_info.exit_instr_len,
            reason,
        }
    }

    fn skip_instruction(&self) {
        let ctx = this_vcpu_mut(self.vm_id).get_ctx_mut();
        ctx.set_rip(ctx.get_rip() + self.exit_instr_len as u64);
    }

    fn handle_exception_nmi(&self, intr_info: u32, intr_errcode: u32) -> Result<(), TdxError> {
        if (intr_info & VMX_INT_INFO_VALID) != 0 {
            this_vcpu_mut(self.vm_id).queue_exception(
                intr_info as u8,
                if (intr_info & VMX_INT_INFO_ERR_CODE_VALID) != 0 {
                    intr_errcode
                } else {
                    0
                },
            )
        } else {
            Ok(())
        }
    }

    fn handle_external_interrupt(&self) {
        // Nothing needs to be done here as external interrupt
        // will be handled by svsm already when enable IRQ after
        // the vmexit happened.
    }

    fn handle_triple_fault(&self) {
        // Handle triple fault vmexit by triggering triple fault
        // to shutdown svsm.
        triple_fault();
    }

    fn handle_init_signal(&self) {
        // Intel SDM Volume 3, 25.2:
        // INIT signals. INIT signals cause VM exits. A logical processer performs none
        // of the operations normally associated with these events. Such exits do not modify
        // register state or clear pending events as they would outside of VMX operation (If
        // a logical processor is the wait-for-SIPI state, INIT signals are blocked. They do
        // not cause VM exits in this case).
        //
        // So, it is safe to ignore the signal.
    }

    fn handle_interrupt_window(&self) {
        this_vcpu(self.vm_id)
            .get_cb()
            .make_request(VcpuReqFlags::DIS_IRQWIN);
    }

    fn handle_cpuid(&self) {
        let ctx = this_vcpu_mut(self.vm_id).get_ctx_mut();
        let vcpuid = this_tdp(self.vm_id).get_vcpuid(
            ctx.get_gpreg(GuestCpuGPRegCode::Rax) as u32,
            ctx.get_gpreg(GuestCpuGPRegCode::Rcx) as u32,
        );

        ctx.set_gpreg(GuestCpuGPRegCode::Rax, vcpuid.eax as u64);
        ctx.set_gpreg(GuestCpuGPRegCode::Rbx, vcpuid.ebx as u64);
        ctx.set_gpreg(GuestCpuGPRegCode::Rcx, vcpuid.ecx as u64);
        ctx.set_gpreg(GuestCpuGPRegCode::Rdx, vcpuid.edx as u64);

        self.skip_instruction();
    }

    fn handle_hlt(&self) {
        disable_irq();
        if !this_vcpu(self.vm_id).has_pending_events() {
            tdvmcall_sti_halt();
        }
        enable_irq();
        self.skip_instruction();
    }

    fn handle_vmcall(&self, cpl: u8) -> Result<(), TdxError> {
        // Doesn't emulate any vmcall but inject #GP or #UD
        if cpl != 0 {
            // Inject GP if vmcall is sending from non-ring0
            Err(TdxError::InjectExcp(ErrExcp::GP(0)))
        } else {
            // Inject UD for other cases
            Err(TdxError::InjectExcp(ErrExcp::UD))
        }
    }

    fn handle_cr(&self, access_type: CrAccessType) -> Result<(), TdxError> {
        let ctx = this_vcpu_mut(self.vm_id).get_ctx_mut();
        match access_type {
            CrAccessType::MovToCr(cr, reg) => {
                let cr_val = ctx.get_gpreg(reg);
                match cr {
                    0 => ctx.set_cr0(cr_val)?,
                    4 => ctx.set_cr4(cr_val)?,
                    8 => this_vcpu_mut(self.vm_id)
                        .get_vlapic_mut()
                        .write_cr8(cr_val)?,
                    _ => {
                        log::error!("Handle CR: Mov to CR{} unsupported", cr);
                        return Err(TdxError::UnSupportedVmExit(VmExitReason::CrAccess {
                            access_type,
                        }));
                    }
                }
            }
            CrAccessType::MovFromCr(cr, reg) => match cr {
                8 => {
                    let cr_val = this_vcpu(self.vm_id).get_vlapic().read_cr8()?;
                    ctx.set_gpreg(reg, cr_val);
                }
                _ => {
                    log::error!("Handle CR: Mov from CR{} unsupported", cr);
                    return Err(TdxError::UnSupportedVmExit(VmExitReason::CrAccess {
                        access_type,
                    }));
                }
            },
            _ => {
                log::error!("Handle CR: unsupported access_type {:?}", access_type);
                return Err(TdxError::UnSupportedVmExit(VmExitReason::CrAccess {
                    access_type,
                }));
            }
        }

        self.skip_instruction();

        Ok(())
    }

    fn handle_io(&self, size: usize, read: bool, string: bool, port: u16) -> Result<(), TdxError> {
        let io_dir = if read {
            IoDirection::Read
        } else {
            IoDirection::Write
        };
        let mut io_req = if string {
            IoReq::new(
                self.vm_id,
                IoType::StringPio {
                    port,
                    instr_len: self.exit_instr_len as usize,
                },
                io_dir,
            )
        } else {
            IoReq::new(self.vm_id, IoType::Pio { port, size }, io_dir)
        };

        io_req.emulate()?;

        if !io_req.need_retry() {
            self.skip_instruction();
        }

        Ok(())
    }

    fn handle_rdmsr(&self) -> Result<(), TdxError> {
        let ctx = this_vcpu_mut(self.vm_id).get_ctx_mut();
        let msr = ctx.get_gpreg(GuestCpuGPRegCode::Rcx) as u32;

        ctx.get_msrs().read(msr).map(|v| {
            // Store the MSR contents in RAX and RDX
            // The high-order 32 bits of each of RAX and RDX are cleared
            ctx.set_gpreg(GuestCpuGPRegCode::Rax, (v as u32).into());
            ctx.set_gpreg(GuestCpuGPRegCode::Rdx, v >> 32);
            self.skip_instruction();
        })
    }

    fn handle_wrmsr(&self) -> Result<(), TdxError> {
        let ctx = this_vcpu_mut(self.vm_id).get_ctx_mut();
        let msr = ctx.get_gpreg(GuestCpuGPRegCode::Rcx) as u32;
        let data = (ctx.get_gpreg(GuestCpuGPRegCode::Rdx) << 32)
            | (ctx.get_gpreg(GuestCpuGPRegCode::Rax) as u32 as u64);

        ctx.get_msrs_mut().write(msr, data).map(|_| {
            self.skip_instruction();
        })
    }

    fn handle_below_threshold(&self) {
        this_vcpu_mut(self.vm_id)
            .get_vlapic_mut()
            .handle_below_threshold_vmexit();
    }

    fn handle_eoi(&self, vec: u8) {
        this_vcpu_mut(self.vm_id)
            .get_vlapic_mut()
            .handle_eoi_vmexit(vec);
    }

    fn handle_page_alias(&self, gpa: GuestPhysAddr, size: PageSize) -> Result<bool, TdxError> {
        let (shared, raw_gpa) = if gpa_is_shared(gpa) {
            (true, gpa_strip_c_bit(gpa))
        } else {
            (false, gpa)
        };

        if !is_guest_phys_addr_valid(raw_gpa) {
            if is_kernel_phys_addr_valid(raw_gpa.to_host_phys_addr()) {
                log::error!(
                    "Add alias for svsm phys addr 0x{:x}",
                    raw_gpa.to_host_phys_addr()
                );
                return Err(TdxError::GuestFatalErr);
            }

            // Represent this is a guest MMIO
            return Ok(false);
        } else if shared {
            // Host VMM can resume L1 instead of enter L2 if injecting
            // interrupt to L1. In this case, L1 will see vmexits from
            // L2. And if this vmexit is EPT_VIOLATION caused by L2 accessing
            // shared GPA, then we can be here. So skip handling for
            // shared GPA.
            return Ok(true);
        }

        // set Read/Write/Execute_supervisor/Valid
        let attr = (GPAAttr::R | GPAAttr::W | GPAAttr::Xs).bits();
        let gpa_attr = attr | GPAAttr::Valid.bits();
        let attr_flags = attr;
        let (tdx_level, len) = match size {
            PageSize::Regular => (0, PAGE_SIZE),
            PageSize::Huge => (1, PAGE_SIZE_2M),
        };

        // Accept memory if has not been accepted
        accept_guest_mem(gpa.page_align(), gpa.page_align() + len)?;

        let gpa_mapping = (gpa.page_align().bits() as u64) | tdx_level;
        td_add_page_alias(self.vm_id, gpa_mapping, gpa_attr, attr_flags)?;

        Ok(true)
    }

    fn handle_ept_violation(
        &self,
        gpa: GuestPhysAddr,
        flags: EPTViolationQualFlags,
    ) -> Result<(), TdxError> {
        // Handle page alias first
        if self.handle_page_alias(gpa, PageSize::Regular)? {
            return Ok(());
        }

        // Not memory address, handle as MMIO
        let io_dir = if flags.contains(EPTViolationQualFlags::R) {
            IoDirection::Read
        } else {
            IoDirection::Write
        };

        let mut io_req = IoReq::new(
            self.vm_id,
            IoType::Mmio {
                addr: gpa,
                instr_len: self.exit_instr_len as usize,
            },
            io_dir,
        );

        io_req.emulate()?;

        if !io_req.need_retry() {
            self.skip_instruction();
        }

        Ok(())
    }

    fn handle_wbinvd(&self) {
        self.skip_instruction();
    }

    fn handle_tdg_vp_vmcall(&self, ctx: &mut GuestCpuContext) {
        let exit_type = ctx.get_gpreg(GuestCpuGPRegCode::R10);
        let leaf = ctx.get_gpreg(GuestCpuGPRegCode::R11);

        if exit_type != 0 {
            log::error!("Not support handling tdg_vm_vmcall exit_type {}", exit_type);
            ctx.set_gpreg(GuestCpuGPRegCode::R10, TDG_VP_VMCALL_INVALID_OPERAND);
            self.skip_instruction();
            return;
        }

        match TdVmCallLeaf::from(leaf) {
            TdVmCallLeaf::MapGpa => {
                let gpa = GuestPhysAddr::from(ctx.get_gpreg(GuestCpuGPRegCode::R12));
                let shared = gpa_is_shared(gpa);
                let start = gpa_strip_c_bit(gpa);
                let size = ctx.get_gpreg(GuestCpuGPRegCode::R13) as usize;
                let end = start + size;

                match convert_guest_mem(start, end, shared) {
                    Ok(size) => {
                        if size == (end - start) {
                            ctx.set_gpreg(GuestCpuGPRegCode::R10, TDG_VP_VMCALL_SUCCESS);
                        } else {
                            ctx.set_gpreg(GuestCpuGPRegCode::R10, TDG_VP_VMCALL_RETRY);
                            ctx.set_gpreg(GuestCpuGPRegCode::R11, u64::from(start + size));
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to handle MapGpa {:?}", e);
                        ctx.set_gpreg(GuestCpuGPRegCode::R10, TDG_VP_VMCALL_INVALID_OPERAND);
                    }
                }
            }
            TdVmCallLeaf::UnSupported => {
                log::error!("Unsupported tdvmcall leaf 0x{:x}", leaf);
                ctx.set_gpreg(GuestCpuGPRegCode::R10, TDG_VP_VMCALL_INVALID_OPERAND);
            }
        }

        self.skip_instruction();
    }

    fn handle_tdg_vp_info(&self, ctx: &mut GuestCpuContext) -> u64 {
        match tdcall_get_td_info() {
            Ok(td_info) => {
                ctx.set_gpreg(GuestCpuGPRegCode::Rcx, td_info.gpaw);
                ctx.set_gpreg(GuestCpuGPRegCode::Rdx, td_info.attributes);
                ctx.set_gpreg(
                    GuestCpuGPRegCode::R8,
                    td_info.num_vcpus as u64 | ((td_info.max_vcpus as u64) << 32),
                );
                ctx.set_gpreg(GuestCpuGPRegCode::R9, td_info.vcpu_index as u64);
                ctx.set_gpreg(GuestCpuGPRegCode::R10, 0);
                ctx.set_gpreg(GuestCpuGPRegCode::R11, 0);

                TDX_SUCCESS
            }
            Err(e) => {
                log::error!("Failed to handle tdg_vp_info: {:?}", e);
                TDX_OPERAND_INVALID
            }
        }
    }

    fn handle_tdcall(&self) {
        let ctx = this_vcpu_mut(self.vm_id).get_ctx_mut();
        let leaf = ctx.get_gpreg(GuestCpuGPRegCode::Rax);

        let tdcall = TdCallLeaf::from(leaf);
        let ret = match tdcall {
            TdCallLeaf::TdgVpVmcall => return self.handle_tdg_vp_vmcall(ctx),
            TdCallLeaf::TdgVpInfo => self.handle_tdg_vp_info(ctx),
            TdCallLeaf::UnSupported => {
                log::error!("Unsupported tdcall leaf {}", leaf);
                TDX_OPERAND_INVALID
            }
        };

        ctx.set_gpreg(GuestCpuGPRegCode::Rax, ret);

        self.skip_instruction();
    }

    fn handle_xsetbv(&self, cpl: u8) -> Result<(), TdxError> {
        let ctx = this_vcpu(self.vm_id).get_ctx();
        let data64 = (ctx.get_gpreg(GuestCpuGPRegCode::Rdx) << 32)
            | (ctx.get_gpreg(GuestCpuGPRegCode::Rax) as u32 as u64);
        let cr4 = CR4Flags::from_bits_truncate(ctx.get_cr4());

        if !this_vcpu(self.vm_id).get_vmcs().is_xsave_enabled()
            || !cr4.contains(CR4Flags::OSXSAVE)
            || !cpu_has_xcr0_features(data64)
        {
            return Err(TdxError::InjectExcp(ErrExcp::UD));
        }

        // to access XCR0,'rcx' reg should be 0
        if cpl == 0
            && ctx.get_gpreg(GuestCpuGPRegCode::Rcx) == 0
            && ((data64 & XCR0Flags::X87.bits()) != 0)
            && ((data64 & XCR0_RSVD) == 0)
        {
            // XCR0[2:1] (SSE state & AVX state) can't not be
            // set to 10b as it is necessary to set both bits
            // to use AVX instructions.
            if data64 & (XCR0Flags::SSE | XCR0Flags::AVX).bits() != XCR0Flags::AVX.bits() {
                write_xcr(data64);
                self.skip_instruction();
                return Ok(());
            }
        }

        Err(TdxError::InjectExcp(ErrExcp::GP(0)))
    }

    pub fn handle_vmexits(&self) -> Result<(), TdxError> {
        match self.reason {
            VmExitReason::ExceptionNMI {
                intr_info,
                intr_errcode,
            } => self.handle_exception_nmi(intr_info, intr_errcode)?,
            VmExitReason::ExternalInterrupt => self.handle_external_interrupt(),
            VmExitReason::TripleFault => self.handle_triple_fault(),
            VmExitReason::InitSignal => self.handle_init_signal(),
            VmExitReason::InterruptWindow => self.handle_interrupt_window(),
            VmExitReason::Cpuid => self.handle_cpuid(),
            VmExitReason::Hlt => self.handle_hlt(),
            VmExitReason::Vmcall { cpl } => self.handle_vmcall(cpl)?,
            VmExitReason::CrAccess { access_type } => self.handle_cr(access_type)?,
            VmExitReason::IoInstruction {
                size,
                read,
                string,
                port,
            } => self.handle_io(size, read, string, port)?,
            VmExitReason::MsrRead => self.handle_rdmsr()?,
            VmExitReason::MsrWrite => self.handle_wrmsr()?,
            VmExitReason::TprBelowThreshold => self.handle_below_threshold(),
            VmExitReason::EoiInduced { vec } => self.handle_eoi(vec),
            VmExitReason::EptViolation { fault_gpa, flags } => {
                self.handle_ept_violation(fault_gpa, flags)?
            }
            VmExitReason::Wbinvd => self.handle_wbinvd(),
            VmExitReason::Xsetbv { cpl } => self.handle_xsetbv(cpl)?,
            VmExitReason::Tdcall => self.handle_tdcall(),
            VmExitReason::UnSupported(v) => {
                log::error!("UnSupported VmExit Reason {}", v);
                return Err(TdxError::InjectExcp(ErrExcp::UD));
            }
        };

        Ok(())
    }
}
