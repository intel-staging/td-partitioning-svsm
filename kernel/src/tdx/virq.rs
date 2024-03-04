// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

use super::error::TdxError;
use super::percpu::{this_vcpu, this_vcpu_mut};
use super::utils::TdpVmId;
use super::vcpu_comm::VcpuReqFlags;
use super::vlapic::Vlapic;
use super::vmcs_lib::{
    VmcsField32Control, VmcsField32Guest, VMX_INTERRUPTABILITY_VCPU_BLOCKED_BY_MOVSS,
    VMX_INTERRUPTABILITY_VCPU_BLOCKED_BY_NMI, VMX_INTERRUPTABILITY_VCPU_BLOCKED_BY_STI,
    VMX_INT_INFO_ERR_CODE_VALID, VMX_INT_INFO_VALID, VMX_INT_TYPE_HW_EXCP, VMX_INT_TYPE_NMI,
    VMX_INT_TYPE_SW_EXCP,
};
use crate::cpu::idt::common::{
    exception_has_err_code, get_exception_class, get_exception_type, ExceptionClass, ExceptionType,
    BP_VECTOR, DF_VECTOR, NMI_VECTOR, OF_VECTOR, PF_VECTOR,
};
use crate::cpu::registers::RFlags;

fn exception_is_soft(vec: u8) -> bool {
    vec as usize == BP_VECTOR || vec as usize == OF_VECTOR
}

struct ExceptionInfo {
    exception: u8,
    err_code: u32,
}

pub struct Virq {
    vm_id: TdpVmId,
    injected: bool,
    excep_info: Option<ExceptionInfo>,
}

impl Virq {
    pub fn init(&mut self, vm_id: TdpVmId) {
        self.vm_id = vm_id;
        self.injected = false;
        self.excep_info = None;
    }

    pub fn reset(&mut self) {
        self.init(self.vm_id);
    }

    fn is_nmi_injectable(&self) -> bool {
        let guest_interruptibility_info = this_vcpu(self.vm_id)
            .get_vmcs()
            .read32(VmcsField32Guest::INTERRUPTIBILITY_INFO);

        (guest_interruptibility_info
            & (VMX_INTERRUPTABILITY_VCPU_BLOCKED_BY_STI
                | VMX_INTERRUPTABILITY_VCPU_BLOCKED_BY_MOVSS
                | VMX_INTERRUPTABILITY_VCPU_BLOCKED_BY_NMI))
            == 0
    }

    // Return true to indicate NMI is injected, otherwise false.
    pub fn inject_nmi(&mut self) -> bool {
        if !self.injected && self.is_nmi_injectable() {
            this_vcpu(self.vm_id).get_vmcs().write32(
                VmcsField32Control::VM_ENTRY_INTR_INFO_FIELD,
                NMI_VECTOR as u32 | VMX_INT_INFO_VALID | VMX_INT_TYPE_NMI,
            );
            self.injected = true;
            true
        } else {
            false
        }
    }

    fn is_guest_irq_enabled(&self) -> bool {
        (this_vcpu(self.vm_id).get_ctx().get_rflags() & RFlags::IF.bits()) != 0
            && (this_vcpu(self.vm_id)
                .get_vmcs()
                .read32(VmcsField32Guest::INTERRUPTIBILITY_INFO)
                & (VMX_INTERRUPTABILITY_VCPU_BLOCKED_BY_STI
                    | VMX_INTERRUPTABILITY_VCPU_BLOCKED_BY_MOVSS))
                == 0
    }

    pub fn inject_intr(&self, vlapic: &mut Vlapic) {
        vlapic.inject_intr(self.is_guest_irq_enabled(), self.injected);
    }

    pub fn post_vmexit(&mut self) {
        self.injected = false;
    }

    pub fn queue_exception(&mut self, vec: u8, err_code: u32) -> Result<VcpuReqFlags, TdxError> {
        if vec >= 32 {
            log::error!("queue_exception: invalid vector {}", vec);
            return Err(TdxError::InvalidVector);
        }

        if let Some(prev_excep_info) = &self.excep_info {
            let prev_vector = prev_excep_info.exception;
            let prev_class = get_exception_class(prev_vector);
            let new_class = get_exception_class(vec);

            if (prev_vector == PF_VECTOR as u8) && (new_class != ExceptionClass::Benign) {
                return Ok(VcpuReqFlags::TRPFAULT);
            } else if ((prev_class == ExceptionClass::Contributory)
                && (new_class == ExceptionClass::Contributory))
                || ((prev_class == ExceptionClass::PageFaults)
                    && (new_class != ExceptionClass::Benign))
            {
                self.excep_info = Some(ExceptionInfo {
                    exception: DF_VECTOR as u8,
                    err_code: 0,
                });
            } else {
                self.excep_info = Some(ExceptionInfo {
                    exception: vec,
                    err_code: if exception_has_err_code(vec) {
                        err_code
                    } else {
                        0
                    },
                });
            }
        } else {
            self.excep_info = Some(ExceptionInfo {
                exception: vec,
                err_code: if exception_has_err_code(vec) {
                    err_code
                } else {
                    0
                },
            });
        }
        Ok(VcpuReqFlags::INJ_EXCP)
    }

    // Return true to indicate exception is injected, otherwise false.
    pub fn inject_exception(&mut self) -> bool {
        if self.injected {
            return false;
        }

        if let Some(excep_info) = self.excep_info.take() {
            let vector = excep_info.exception;
            let vmcs = this_vcpu(self.vm_id).get_vmcs();

            let err_code_valid = if exception_has_err_code(vector) {
                vmcs.write32(
                    VmcsField32Control::VM_ENTRY_EXCEPTION_ERROR_CODE,
                    excep_info.err_code,
                );
                VMX_INT_INFO_ERR_CODE_VALID
            } else {
                0u32
            };

            let intr_type = if exception_is_soft(vector) {
                let instr_len = vmcs.read32(VmcsField32Control::VM_ENTRY_INSTRUCTION_LEN);
                vmcs.write32(VmcsField32Control::VM_ENTRY_INSTRUCTION_LEN, instr_len);
                VMX_INT_TYPE_SW_EXCP
            } else {
                VMX_INT_TYPE_HW_EXCP
            };

            vmcs.write32(
                VmcsField32Control::VM_ENTRY_INTR_INFO_FIELD,
                vector as u32 | VMX_INT_INFO_VALID | err_code_valid | intr_type,
            );

            if get_exception_type(vector) == ExceptionType::Fault {
                // SDM 17.3.1.1 For any fault-class exception except a debug
                // exception generated in response to an instruction
                // breakpoint, the value pushed for RF is 1. #DB is treated
                // as Trap in get_exception_type, so RF will not be set for
                // instruction breakpoint.
                let ctx = this_vcpu_mut(self.vm_id).get_ctx_mut();
                ctx.set_rflags(ctx.get_rflags() | RFlags::RF.bits());
            }

            self.injected = true;
        }

        self.injected
    }
}
