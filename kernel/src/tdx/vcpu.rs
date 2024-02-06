// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

use super::gctx::GuestCpuContext;
use super::tdcall::tdvmcall_sti_halt;
use super::utils::TdpVmId;
use super::vmcs::Vmcs;
use crate::cpu::interrupts::{disable_irq, enable_irq};

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

pub struct Vcpu {
    vm_id: TdpVmId,
    apic_id: u32,
    is_bsp: bool,
    cur_state: VcpuState,
    vmcs: Vmcs,
    ctx: GuestCpuContext,
}

impl Vcpu {
    pub fn init(&mut self, vm_id: TdpVmId, apic_id: u32, is_bsp: bool) {
        self.vm_id = vm_id;
        self.apic_id = apic_id;
        self.is_bsp = is_bsp;
        self.cur_state = VcpuState::Zombie;
        self.vmcs.init(vm_id, apic_id);
        self.ctx.init(vm_id);
    }

    pub fn get_vmcs(&self) -> &Vmcs {
        &self.vmcs
    }

    pub fn run(&mut self) {
        if self.is_bsp {
            self.update_cur_state(VcpuState::PowerOnReset);
        }

        loop {
            match self.cur_state {
                VcpuState::Zombie | VcpuState::WaitForSipi => {
                    // TODO: Check if any new state is requested
                    self.idle();
                }
                VcpuState::PowerOnReset => {
                    self.reset();
                    self.update_cur_state(VcpuState::Inited);
                }
                VcpuState::Inited => {
                    self.configure_vmcs();
                    self.update_cur_state(VcpuState::Running);
                }
                VcpuState::InitKicked => self.update_cur_state(VcpuState::WaitForSipi),
                VcpuState::SipiKicked(_) => self.update_cur_state(VcpuState::Running),
                VcpuState::Running => {
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

    fn reset(&mut self) {
        self.ctx.reset();
    }

    fn configure_vmcs(&mut self) {
        self.vmcs.init_exec_ctrl();
        self.vmcs.init_entry_ctrl();
        self.vmcs.init_exit_ctrl();
    }
}
