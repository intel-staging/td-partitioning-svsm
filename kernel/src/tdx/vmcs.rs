// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::utils::TdpVmId;
use super::vmcs_lib::VmcsAccess;
use crate::cpu::msr::{
    read_msr, MSR_VMX_PROCBASED_CTLS2, MSR_VMX_TRUE_ENTRY_CTLS, MSR_VMX_TRUE_PROCBASED_CTLS,
};
use crate::cpu::percpu::this_cpu;
use lazy_static::lazy_static;

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

struct VmCtrlCheck32 {
    default: u32,
    set: u32,
    clear: u32,
}

#[allow(dead_code)]
enum VmCtrlType32 {
    PrimaryVmExec(VmCtrlCheck32),
    SecondaryVmExec(VmCtrlCheck32),
    VmEntryCtrl(VmCtrlCheck32),
}

#[derive(Clone, Copy)]
struct VmxAllowedBits {
    // Bits are 1 in allowed0 as fixed-1.
    allowed0: u32,
    // Bits are 0 in allowed1 as fixed-0.
    allowed1: u32,
}

impl VmxAllowedBits {
    fn new(msr: u64) -> Self {
        Self {
            allowed0: msr as u32,
            allowed1: (msr >> 32) as u32,
        }
    }
}

#[derive(Clone, Copy)]
struct VmcsCaps {
    primary_vmexec: VmxAllowedBits,
    secondary_vmexec: VmxAllowedBits,
    vmentry_ctrl: VmxAllowedBits,
}

lazy_static! {
    static ref VMCS_CAPS: VmcsCaps = VmcsCaps::new();
}

#[allow(dead_code)]
impl VmcsCaps {
    fn new() -> Self {
        VmcsCaps {
            primary_vmexec: VmxAllowedBits::new(read_msr(MSR_VMX_TRUE_PROCBASED_CTLS).unwrap()),
            // As TD always has "activate secondary controls" and "activate tertiary
            // controls" in vm-execute control, directly access the corresponding MSR
            secondary_vmexec: VmxAllowedBits::new(read_msr(MSR_VMX_PROCBASED_CTLS2).unwrap()),
            vmentry_ctrl: VmxAllowedBits::new(read_msr(MSR_VMX_TRUE_ENTRY_CTLS).unwrap()),
        }
    }

    fn calc_valid_vm_ctrl32(
        &self,
        allowed_bits: VmxAllowedBits,
        check: VmCtrlCheck32,
    ) -> Option<u32> {
        if check.clear & allowed_bits.allowed0 != 0 {
            return None;
        }

        // The bits read-only to L1 VMM is enumerated as fixed-0 althrough the bits
        // value in VMCS field might be 1. This is the Non-Standard Behavior of Virtual
        // IA32_VMX_* MSRs defined in TDP spec 23.1.2. For those bits, use default value.
        let set_fixed0 = check.set & !allowed_bits.allowed1;
        let value32 =
            (check.set & !set_fixed0) | (check.default & set_fixed0) | allowed_bits.allowed0;

        if value32 & check.set != check.set {
            None
        } else {
            Some(value32)
        }
    }

    fn is_vm_ctrl32_valid(&self, allowed_bits: VmxAllowedBits, set: u32) -> bool {
        // The bits set should be 1 in allowed1
        (set & allowed_bits.allowed1) == set
    }

    fn check_vm_ctrl32(&self, feat: VmCtrlType32) -> Option<u32> {
        match feat {
            VmCtrlType32::PrimaryVmExec(v) => self.calc_valid_vm_ctrl32(self.primary_vmexec, v),
            VmCtrlType32::SecondaryVmExec(v) => self.calc_valid_vm_ctrl32(self.secondary_vmexec, v),
            VmCtrlType32::VmEntryCtrl(v) => self.calc_valid_vm_ctrl32(self.vmentry_ctrl, v),
        }
    }

    fn allow_set_vm_ctrl32(&self, feat: VmCtrlType32) -> bool {
        match feat {
            VmCtrlType32::PrimaryVmExec(v) => self.is_vm_ctrl32_valid(self.primary_vmexec, v.set),
            VmCtrlType32::SecondaryVmExec(v) => {
                self.is_vm_ctrl32_valid(self.secondary_vmexec, v.set)
            }
            VmCtrlType32::VmEntryCtrl(v) => self.is_vm_ctrl32_valid(self.vmentry_ctrl, v.set),
        }
    }
}
