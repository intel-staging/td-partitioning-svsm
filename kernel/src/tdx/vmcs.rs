// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::utils::TdpVmId;
use super::vmcs_lib::VmcsAccess;
use crate::cpu::percpu::this_cpu;

pub struct Vmcs {
    vm_id: TdpVmId,
    apic_id: u32,
}

#[allow(dead_code)]
impl Vmcs {
    pub fn init(&mut self, vm_id: TdpVmId, apic_id: u32) {
        self.vm_id = vm_id;
        self.apic_id = apic_id;
    }

    // TDP guest VMCS accessing should be happened on the
    // CPU which is assigned as VMCS migrating between CPUs
    // are not supported.
    fn on_cpu_check(&self) {
        assert!(this_cpu().get_apic_id() == self.apic_id);
    }

    pub fn read16(&self, field: impl VmcsAccess<T = u16>) -> u16 {
        self.on_cpu_check();
        field.read(self.vm_id)
    }

    pub fn write16(&self, field: impl VmcsAccess<T = u16>, value: u16) {
        self.on_cpu_check();
        field.write(self.vm_id, value);
    }

    pub fn read32(&self, field: impl VmcsAccess<T = u32>) -> u32 {
        self.on_cpu_check();
        field.read(self.vm_id)
    }

    pub fn write32(&self, field: impl VmcsAccess<T = u32>, value: u32) {
        self.on_cpu_check();
        field.write(self.vm_id, value);
    }

    pub fn read64(&self, field: impl VmcsAccess<T = u64>) -> u64 {
        self.on_cpu_check();
        field.read(self.vm_id)
    }

    pub fn write64(&self, field: impl VmcsAccess<T = u64>, value: u64) {
        self.on_cpu_check();
        field.write(self.vm_id, value);
    }
}
