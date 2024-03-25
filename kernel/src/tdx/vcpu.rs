// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

extern crate alloc;

use super::error::{ErrExcp, TdxError};
use super::gctx::{GuestCpuContext, GuestCpuSegCode};
use super::interrupts::VCPU_KICK_VECTOR;
use super::tdcall::tdvmcall_sti_halt;
use super::tdp::this_tdp;
use super::utils::{td_flush_vpid_global, td_invept, td_vp_enter, L2ExitInfo, TdpVmId, VpEnterRet};
use super::vcpu_comm::{VcpuCommBlock, VcpuReqFlags};
use super::virq::Virq;
use super::vlapic::Vlapic;
use super::vmcs::Vmcs;
use super::vmcs_lib::VmcsField32ReadOnly;
use super::vmexit::VmExit;
use crate::cpu::idt::common::{GP_VECTOR, PF_VECTOR, UD_VECTOR};
use crate::cpu::interrupts::{disable_irq, enable_irq};
use crate::cpu::lapic::LAPIC;
use crate::cpu::msr::{write_msr, MSR_IA32_PAT, MSR_IA32_PRED_CMD};
use alloc::sync::Arc;

const DR7_INIT_VALUE: u64 = 0x400;

// VcpuState machine:
// BSP:Zombie -> PowerOnReset -> Inited -> Running
// AP: Zombie -> InitKicked -> WaitForSipi -> SipiKicked -> Running
//
// In Zombie/WaitForSipi/Running, needs check if new state is requested.
// For the other state, the state machine is transfered automatically.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum VcpuState {
    // Waiting for initialization, or transfered from Running for reset.
    Zombie,
    // Transfered from Zombie and got prepared to init
    PowerOnReset,
    // Transfered from PowerOnReset and ready to run
    Inited,
    // Transfered from Zombie which is kicked by init signal
    InitKicked,
    // Transfered from InitKicked and waiting for sipi
    WaitForSipi,
    // Transfered from WaitForSipi which is kicked by sipi signal and ready to run
    SipiKicked(u64),
    // Transfered from Inited or SipiKicked and start to run
    Running,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ResetMode {
    PowerOnReset, // Reset after power on
    InitReset,    // Reset after init signal
}

pub struct Vcpu {
    vm_id: TdpVmId,
    apic_id: u32,
    is_bsp: bool,
    cur_state: VcpuState,
    vmcs: Vmcs,
    ctx: GuestCpuContext,
    cb: Arc<VcpuCommBlock>,
    vlapic: Vlapic,
    virq: Virq,
}

impl Vcpu {
    pub fn init(&mut self, vm_id: TdpVmId, apic_id: u32, is_bsp: bool) {
        self.vm_id = vm_id;
        self.apic_id = apic_id;
        self.is_bsp = is_bsp;
        self.cur_state = VcpuState::Zombie;
        self.vmcs.init(vm_id, apic_id);
        self.ctx.init(vm_id);
        self.vlapic.init(vm_id, apic_id, is_bsp);
        self.virq.init(vm_id);
        let cb = Arc::new(VcpuCommBlock::new(apic_id, self.vlapic.regs_reader()));
        this_tdp(vm_id).register_vcpu_cb(cb.clone());
        unsafe { core::ptr::write(core::ptr::addr_of_mut!(self.cb), cb) };
    }

    pub fn get_vmcs(&self) -> &Vmcs {
        &self.vmcs
    }

    pub fn get_ctx(&self) -> &GuestCpuContext {
        &self.ctx
    }

    pub fn get_ctx_mut(&mut self) -> &mut GuestCpuContext {
        &mut self.ctx
    }

    pub fn get_vlapic(&self) -> &Vlapic {
        &self.vlapic
    }

    pub fn get_vlapic_mut(&mut self) -> &mut Vlapic {
        &mut self.vlapic
    }

    pub fn get_cb(&self) -> &Arc<VcpuCommBlock> {
        &self.cb
    }

    pub fn apic_id(&self) -> u32 {
        self.apic_id
    }

    pub fn run(&mut self) {
        if self.is_bsp {
            self.update_cur_state(VcpuState::PowerOnReset);
            loop {
                // Wait untils all AP vCPUs complete the VcpuCommBlock
                // registration to Tdp.
                if this_tdp(self.vm_id).vcpu_cbs_ready() {
                    break;
                }
                self.idle()
            }
        }

        loop {
            match self.cur_state {
                VcpuState::Zombie | VcpuState::WaitForSipi => {
                    if let Some(state) = self.cb.get_pending_state() {
                        self.update_cur_state(state);
                    } else {
                        self.idle();
                    }
                }
                VcpuState::PowerOnReset => {
                    self.reset(ResetMode::PowerOnReset);
                    self.update_cur_state(VcpuState::Inited);
                }
                VcpuState::Inited => {
                    self.configure_vmcs();
                    self.update_cur_state(VcpuState::Running);
                }
                VcpuState::InitKicked => {
                    self.reset(ResetMode::InitReset);
                    self.update_cur_state(VcpuState::WaitForSipi);
                }
                VcpuState::SipiKicked(sipi_vector) => {
                    let mut cs_sel = self.ctx.get_seg(GuestCpuSegCode::CS);
                    cs_sel.selector = ((sipi_vector >> 4) & 0xffff) as u16;
                    cs_sel.base = (cs_sel.selector as u64) << 4;
                    self.ctx.set_seg(GuestCpuSegCode::CS, cs_sel);
                    self.ctx.set_rip(0);
                    self.configure_vmcs();
                    self.update_cur_state(VcpuState::Running);
                }
                VcpuState::Running => {
                    // Before handling request, disable IRQ until entering TDP guest so that
                    // the external interrupt can kick TDP guest out, and L1 VMM can handle
                    // the requests generated by the IRQ handler in the next vmenter cycle.
                    disable_irq();
                    if let Err(e) = self.handle_request() {
                        log::error!(
                            "vcpu{} handling pending request failed: {:x?}",
                            self.apic_id,
                            e
                        );
                        self.update_cur_state(VcpuState::Zombie);
                        continue;
                    }
                    let l2exit_info = self.vmenter();
                    enable_irq();

                    // With pending interrupt in svsm, vmenter actually didn't
                    // happen so there is no valid vmexit reason to handle.
                    if let Some(l2exit_info) = l2exit_info {
                        // Check undelivered event first before handle the real vmexit reasons
                        match self.virq.check_undelivered_event(
                            l2exit_info.idt_vec_info,
                            l2exit_info.idt_vec_errcode,
                        ) {
                            Err(e) => {
                                log::error!(
                                    "vcpu{} failed to check undelivered event: {:?}",
                                    self.apic_id,
                                    e
                                );
                            }
                            Ok(Some(req)) => self.cb.make_request(req),
                            Ok(None) => {}
                        }

                        let vmexit = VmExit::new(self.vm_id, l2exit_info);
                        if let Err(e) = vmexit.handle_vmexits() {
                            log::error!(
                                "vcpu{} handle vmexit {:x?} failed: {:x?}",
                                self.apic_id,
                                vmexit.reason,
                                e
                            );
                            match e {
                                TdxError::InjectExcp(excp) => match excp {
                                    ErrExcp::GP(ec) => self
                                        .queue_exception(GP_VECTOR as u8, ec)
                                        .expect("Failed to inject #GP"),
                                    ErrExcp::UD => self
                                        .queue_exception(UD_VECTOR as u8, 0)
                                        .expect("Failed to inject #UD"),
                                    ErrExcp::PF(gva, ec) => {
                                        self.ctx.set_cr2(u64::from(gva)).unwrap();
                                        self.queue_exception(PF_VECTOR as u8, ec.bits())
                                            .expect("Failed to inject #PF");
                                    }
                                },
                                _ => self
                                    .queue_exception(GP_VECTOR as u8, 0)
                                    .expect("Failed to inject #GP"),
                            }
                        }
                    }

                    if let Some(state) = self.cb.get_pending_state() {
                        self.update_cur_state(state);
                    }
                }
            }
        }
    }

    fn update_cur_state(&mut self, new_state: VcpuState) {
        if self.cur_state == new_state {
            return;
        }

        // Refer to the comment for VcpuState
        let state = match self.cur_state {
            VcpuState::Zombie => match new_state {
                VcpuState::InitKicked | VcpuState::PowerOnReset => Some(new_state),
                _ => None,
            },
            VcpuState::PowerOnReset => match new_state {
                VcpuState::Inited => Some(new_state),
                _ => None,
            },
            VcpuState::InitKicked => match new_state {
                VcpuState::WaitForSipi => Some(new_state),
                _ => None,
            },
            VcpuState::WaitForSipi => match new_state {
                VcpuState::SipiKicked(_) => Some(new_state),
                _ => None,
            },
            VcpuState::Inited | VcpuState::SipiKicked(_) => match new_state {
                VcpuState::Running => Some(new_state),
                _ => None,
            },
            VcpuState::Running => match new_state {
                VcpuState::SipiKicked(_) => {
                    // new cpu model only need one SIPI to kick AP run,
                    // the second SIPI will be ignored as it move out of
                    // wait-for-SIPI state.
                    Some(self.cur_state)
                }
                VcpuState::Zombie => Some(new_state),
                _ => None,
            },
        };

        if let Some(state) = state {
            self.cur_state = state;
        } else {
            panic!(
                "vcpu{} state transation from {:x?} to {:x?} is not allowed",
                self.apic_id, self.cur_state, new_state,
            );
        }
    }

    fn idle(&self) {
        disable_irq();
        tdvmcall_sti_halt();
        enable_irq();
    }

    fn reset(&mut self, mode: ResetMode) {
        self.ctx.reset();
        self.vlapic.reset(mode);
        self.virq.reset();
    }

    fn configure_vmcs(&mut self) {
        let vlapic_page_pa = self.vlapic.get_apic_page_addr();
        self.vmcs.init_exec_ctrl(vlapic_page_pa);
        self.vmcs.init_entry_ctrl();
        self.vmcs.init_exit_ctrl();

        let msrs = self.ctx.get_msrs();
        self.vmcs
            .init_guest_state(msrs.read(MSR_IA32_PAT).unwrap(), DR7_INIT_VALUE);

        // A power-up or a reset invalidates all linear mappings,
        // guest-physical mappings, and combined mappings
        td_flush_vpid_global(self.vm_id);
    }

    fn handle_request(&mut self) -> Result<(), TdxError> {
        if self.cb.test_and_clear_request(VcpuReqFlags::TRPFAULT) {
            return Err(TdxError::GuestFatalErr);
        }

        if self.cb.test_and_clear_request(VcpuReqFlags::EN_X2APICV) {
            self.vmcs.enable_x2apic_virtualization();
            self.ctx.get_msrs_mut().update_msr_bitmap_x2apic_apicv();
        }

        if self.cb.test_and_clear_request(VcpuReqFlags::VTIMER) {
            self.vlapic.handle_expired_timer();
        }

        if self.cb.test_and_clear_request(VcpuReqFlags::SIRTE) {
            this_tdp(self.vm_id).get_sirte().handle_sirte();
        }

        if self.cb.test_and_clear_request(VcpuReqFlags::FLUSH_EPT) {
            td_invept(self.vm_id);
        }

        if self.cb.test_and_clear_request(VcpuReqFlags::INJ_EXCP) {
            // Handle exception request first
            if !self.virq.inject_exception() {
                // Exception is not injected, set the INJ_EXCP request again
                self.cb.make_request(VcpuReqFlags::INJ_EXCP);
            }
        } else if self.cb.test_and_clear_request(VcpuReqFlags::INJ_NMI) {
            // Handle NMI request in the next
            if !self.virq.inject_nmi() {
                // NMI not injected, set the INJ_NMI request again.
                self.cb.make_request(VcpuReqFlags::INJ_NMI);
            }
        } else {
            // Handle pending vector injection after exception/NMI.
            self.virq.inject_pending_idt();
        }

        // Handle interrupt event after nmi/exceptions
        if self.cb.test_and_clear_request(VcpuReqFlags::REQ_EVENT) {
            self.virq.inject_intr(&mut self.vlapic, &self.cb);
        }

        if self.cb.has_request(VcpuReqFlags::INJ_NMI) || self.vlapic.has_pending_delivery_intr() {
            // Clear the DIS_IRQWIN request as irq window should be enabled
            self.cb.clear_request(VcpuReqFlags::DIS_IRQWIN);
            // Enable IRQ windown if there is pending event not injected
            self.vmcs.enable_irq_window();
        } else if self.cb.test_and_clear_request(VcpuReqFlags::DIS_IRQWIN) {
            // Disable irq window if the window is opened and there is no
            // pending events to inject
            self.vmcs.disable_irq_window();
        }

        Ok(())
    }

    fn vmenter(&mut self) -> Option<L2ExitInfo> {
        let pa = self.ctx.pre_vmentry();

        // Prevent L1 VMM from using the predicted branch targets before switching to L2 VM,
        // PRED_SET_IBPB = 1
        write_msr(MSR_IA32_PRED_CMD, 1).unwrap();

        match td_vp_enter(self.vm_id, pa) {
            VpEnterRet::L2Exit(l2exit_info) => {
                // Prevent L2 VM from using the predicted branch targets before switching to L1 VMM
                write_msr(MSR_IA32_PRED_CMD, 1).unwrap();

                self.ctx.post_vmexit();
                self.virq.post_vmexit();
                Some(l2exit_info)
            }
            VpEnterRet::NoL2Enter => None,
            VpEnterRet::Error(exit_reason, status) => {
                // Prevent L2 VM from using the predicted branch targets before switching to L1 VMM
                write_msr(MSR_IA32_PRED_CMD, 1).unwrap();

                panic!(
                    "td_vp_enter fail: reason {:#08x} status {:#08x} err_inst {:#08x}",
                    exit_reason,
                    status,
                    self.vmcs.read32(VmcsField32ReadOnly::VM_INSTRUCTION_ERROR)
                );
            }
        }
    }

    pub fn queue_exception(&mut self, vec: u8, err_code: u32) -> Result<(), TdxError> {
        self.virq
            .queue_exception(vec, err_code)
            .map(|req| self.cb.make_request(req))
    }

    pub fn has_pending_events(&self) -> bool {
        !self.cb.is_request_empty() || self.vlapic.has_pending_intr()
    }
}

pub fn kick_vcpu(apic_id: u32) {
    if LAPIC.id() != apic_id {
        (*LAPIC).send_ipi(apic_id, VCPU_KICK_VECTOR);
    }
}
