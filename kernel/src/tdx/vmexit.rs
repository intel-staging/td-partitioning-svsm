// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::error::{ErrExcp, TdxError};
use super::percpu::this_vcpu;
use super::utils::{L2ExitInfo, TdpVmId};
use super::vcpu_comm::VcpuReqFlags;

#[derive(Copy, Clone, Debug)]
pub enum VmExitReason {
    ExternalInterrupt,
    InitSignal,
    InterruptWindow,
    UnSupported(u32),
}

impl VmExitReason {
    fn new(l2exit_info: &L2ExitInfo) -> Self {
        let exit_reason = l2exit_info.exit_reason;
        match exit_reason {
            1 => VmExitReason::ExternalInterrupt,
            3 => VmExitReason::InitSignal,
            7 => VmExitReason::InterruptWindow,
            _ => VmExitReason::UnSupported(exit_reason),
        }
    }
}

pub struct VmExit {
    vm_id: TdpVmId,
    pub reason: VmExitReason,
}

impl VmExit {
    pub fn new(vm_id: TdpVmId, l2exit_info: L2ExitInfo) -> Self {
        let reason = VmExitReason::new(&l2exit_info);
        VmExit { vm_id, reason }
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

    pub fn handle_vmexits(&self) -> Result<(), TdxError> {
        match self.reason {
            VmExitReason::ExternalInterrupt => self.handle_external_interrupt(),
            VmExitReason::InitSignal => self.handle_init_signal(),
            VmExitReason::InterruptWindow => self.handle_interrupt_window(),
            VmExitReason::UnSupported(v) => {
                log::error!("UnSupported VmExit Reason {}", v);
                return Err(TdxError::InjectExcp(ErrExcp::UD));
            }
        };

        Ok(())
    }
}
