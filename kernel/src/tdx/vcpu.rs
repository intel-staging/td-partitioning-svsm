// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

use super::utils::TdpVmId;

pub struct Vcpu {
    vm_id: TdpVmId,
    apic_id: u32,
    is_bsp: bool,
}

impl Vcpu {
    pub fn init(&mut self, vm_id: TdpVmId, apic_id: u32, is_bsp: bool) {
        self.vm_id = vm_id;
        self.apic_id = apic_id;
        self.is_bsp = is_bsp;
    }

    pub fn run(&mut self) {
        //TODO: add vcpu run loop
    }
}
