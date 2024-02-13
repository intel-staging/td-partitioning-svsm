// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::error::{ErrExcp, TdxError};
use super::gctx::GuestCpuGPRegCode;
use super::percpu::{this_vcpu, this_vcpu_mut};
use super::utils::{L2ExitInfo, TdpVmId};
use super::vcpu_comm::VcpuReqFlags;
use super::vmcs_lib::{VMX_INT_INFO_ERR_CODE_VALID, VMX_INT_INFO_VALID};

#[derive(Copy, Clone, Debug)]
pub enum VmExitReason {
    ExceptionNMI { intr_info: u32, intr_errcode: u32 },
    ExternalInterrupt,
    InitSignal,
    InterruptWindow,
    MsrRead,
    MsrWrite,
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
            VmExitReason::UnSupported(v) => {
                log::error!("UnSupported VmExit Reason {}", v);
                return Err(TdxError::InjectExcp(ErrExcp::UD));
            }
        };

        Ok(())
    }
}
