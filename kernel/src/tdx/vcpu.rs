// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

extern crate alloc;

use super::gctx::GuestCpuContext;
use super::interrupts::VCPU_KICK_VECTOR;
use super::tdcall::tdvmcall_sti_halt;
use super::tdp::this_tdp;
use super::utils::{td_flush_vpid_global, td_vp_enter, L2ExitInfo, TdpVmId, VpEnterRet};
use super::vcpu_comm::{VcpuCommBlock, VcpuReqFlags};
use super::vlapic::Vlapic;
use super::vmcs::Vmcs;
use super::vmcs_lib::VmcsField32ReadOnly;
use super::vmexit::VmExit;
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
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum VcpuState {
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
        let cb = Arc::new(VcpuCommBlock::new(apic_id));
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
                    // TODO: Check if any new state is requested
                    self.idle();
                }
                VcpuState::PowerOnReset => {
                    self.reset(ResetMode::PowerOnReset);
                    self.update_cur_state(VcpuState::Inited);
                }
                VcpuState::Inited => {
                    self.configure_vmcs();
                    self.update_cur_state(VcpuState::Running);
                }
                VcpuState::InitKicked => self.update_cur_state(VcpuState::WaitForSipi),
                VcpuState::SipiKicked(_) => self.update_cur_state(VcpuState::Running),
                VcpuState::Running => {
                    self.handle_request();
                    let l2exit_info = self.vmenter();

                    // With pending interrupt in svsm, vmenter actually didn't
                    // happen so there is no valid vmexit reason to handle.
                    if let Some(l2exit_info) = l2exit_info {
                        //TODO: handle undelivered event first.
                        let vmexit = VmExit::new(l2exit_info);
                        if let Err(e) = vmexit.handle_vmexits() {
                            log::error!(
                                "vcpu{} handle vmexit {:x?} failed: {:x?}",
                                self.apic_id,
                                vmexit.reason,
                                e
                            );
                        }
                    }
                    // TODO: Check if any new state is requested
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

    fn handle_request(&mut self) {
        if self.cb.test_and_clear_request(VcpuReqFlags::EN_X2APICV) {
            self.vmcs.enable_x2apic_virtualization();
            self.ctx.get_msrs_mut().update_msr_bitmap_x2apic_apicv();
        }
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
}

pub fn kick_vcpu(apic_id: u32) {
    if LAPIC.id() != apic_id {
        (*LAPIC).send_ipi(apic_id, VCPU_KICK_VECTOR);
    }
}
