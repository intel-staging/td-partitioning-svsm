// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::error::{ErrExcp, TdxError};
use super::gctx::GuestCpuGPRegCode;
use super::gmem::accept_guest_mem;
use super::percpu::{this_vcpu, this_vcpu_mut};
use super::utils::{td_add_page_alias, GPAAttr, L2ExitInfo, TdpVmId};
use super::vcpu_comm::VcpuReqFlags;
use super::vmcs_lib::{VMX_INT_INFO_ERR_CODE_VALID, VMX_INT_INFO_VALID};
use crate::address::{Address, GuestPhysAddr};
use crate::mm::address_space::is_kernel_phys_addr_valid;
use crate::mm::guestmem::{gpa_is_shared, gpa_strip_c_bit};
use crate::mm::memory::is_guest_phys_addr_valid;
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};

#[derive(Copy, Clone, Debug)]
pub enum VmExitReason {
    ExceptionNMI { intr_info: u32, intr_errcode: u32 },
    ExternalInterrupt,
    InitSignal,
    InterruptWindow,
    MsrRead,
    MsrWrite,
    EptViolation { fault_gpa: GuestPhysAddr },
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
            3 => VmExitReason::InitSignal,
            7 => VmExitReason::InterruptWindow,
            31 => VmExitReason::MsrRead,
            32 => VmExitReason::MsrWrite,
            48 => VmExitReason::EptViolation {
                fault_gpa: GuestPhysAddr::from(l2exit_info.fault_gpa),
            },
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

    fn handle_ept_violation(&self, gpa: GuestPhysAddr) -> Result<(), TdxError> {
        // Handle page alias first
        if self.handle_page_alias(gpa, PageSize::Regular)? {
            return Ok(());
        }

        //TODO: The EPT violation is caused by accessing virtual MMIO.
        //Add MMIO emulation support.
        panic!("MMIO emulation not supported yet");
    }

    pub fn handle_vmexits(&self) -> Result<(), TdxError> {
        match self.reason {
            VmExitReason::ExceptionNMI {
                intr_info,
                intr_errcode,
            } => self.handle_exception_nmi(intr_info, intr_errcode)?,
            VmExitReason::ExternalInterrupt => self.handle_external_interrupt(),
            VmExitReason::InitSignal => self.handle_init_signal(),
            VmExitReason::InterruptWindow => self.handle_interrupt_window(),
            VmExitReason::MsrRead => self.handle_rdmsr()?,
            VmExitReason::MsrWrite => self.handle_wrmsr()?,
            VmExitReason::EptViolation { fault_gpa } => self.handle_ept_violation(fault_gpa)?,
            VmExitReason::UnSupported(v) => {
                log::error!("UnSupported VmExit Reason {}", v);
                return Err(TdxError::InjectExcp(ErrExcp::UD));
            }
        };

        Ok(())
    }
}
