// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

use super::percpu::this_vcpu;
use super::utils::TdpVmId;
use super::vlapic::Vlapic;
use super::vmcs_lib::{
    VmcsField32Control, VmcsField32Guest, VMX_INTERRUPTABILITY_VCPU_BLOCKED_BY_MOVSS,
    VMX_INTERRUPTABILITY_VCPU_BLOCKED_BY_NMI, VMX_INTERRUPTABILITY_VCPU_BLOCKED_BY_STI,
    VMX_INT_INFO_VALID, VMX_INT_TYPE_NMI,
};
use crate::cpu::idt::common::NMI_VECTOR;
use crate::cpu::registers::RFlags;

pub struct Virq {
    vm_id: TdpVmId,
    injected: bool,
}

impl Virq {
    pub fn init(&mut self, vm_id: TdpVmId) {
        self.vm_id = vm_id;
        self.injected = false;
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
}
