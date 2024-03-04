// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author:
//      Chuanxiao Dong <chuanxiao.dong@intel.com>
//      Jason CJ Chen <jason.cj.chen@intel.com>

use super::utils::TdpVmId;
use super::vcr::{get_cr0_guest_host_mask, get_cr4_guest_host_mask};
use super::vmcs_lib::{
    PrimaryVmExecControls, SecondaryVmExecControls, VmEntryControls, VmcsAccess,
    VmcsField32Control, VmcsField32Guest, VmcsField64Control, VmcsField64Guest,
};
use crate::address::PhysAddr;
use crate::cpu::features::{cpu_has_feature, X86_FEATURE_INVPCID};
use crate::cpu::idt::common::MCE_VECTOR;
use crate::cpu::msr::{
    read_msr, MSR_VMX_PROCBASED_CTLS2, MSR_VMX_TRUE_ENTRY_CTLS, MSR_VMX_TRUE_PROCBASED_CTLS,
};
use crate::cpu::percpu::this_cpu;
use lazy_static::lazy_static;

pub struct Vmcs {
    vm_id: TdpVmId,
    apic_id: u32,
    proc_vm_exec_ctrls: u32,
    xsave_enabled: bool,
}

impl Vmcs {
    pub fn init(&mut self, vm_id: TdpVmId, apic_id: u32) {
        self.vm_id = vm_id;
        self.apic_id = apic_id;
        self.proc_vm_exec_ctrls = 0;
        self.xsave_enabled = false;
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

    pub fn init_exec_ctrl(&mut self, vlapic_page_pa: PhysAddr) {
        // All the bits in Pin based VM execution control are
        // read-only to L1 VMM. Skip set up this control field.
        //
        // Set up primary processor based VM execution controls
        // with RW bits:
        // Enable TPR emulation as vlapic will start from xapic mode.
        // RDPMC cause VM exit
        let set = (PrimaryVmExecControls::CR8_LOAD_EXITING
            | PrimaryVmExecControls::CR8_STORE_EXITING
            | PrimaryVmExecControls::RDPMC_EXITING)
            .bits();

        // Disable VM exit for CR3 access
        // Disable VM exit for INVLPG
        let clear = (PrimaryVmExecControls::CR3_LOAD_EXITING
            | PrimaryVmExecControls::CR3_STORE_EXITING
            | PrimaryVmExecControls::INVLPG_EXITING)
            .bits();

        self.proc_vm_exec_ctrls = VMCS_CAPS
            .check_vm_ctrl32(VmCtrlType32::PrimaryVmExec(VmCtrlCheck32 {
                default: self.read32(VmcsField32Control::PROC_BASED_VM_EXEC_CONTROL),
                set,
                clear,
            }))
            .unwrap();

        // Set up secondary processor based VM execution controls with
        // RW bits:
        // Enable RDTSCP
        // Enable INVPCID
        // Enable XSAVE
        let mut set = (SecondaryVmExecControls::RDTSCP
            | SecondaryVmExecControls::INVPCID
            | SecondaryVmExecControls::XSAVES)
            .bits();

        // SDM Vol3, 25.3, setting "enable INVPCID" VM-execution to 1 with
        // "INVLPG exiting" disabled, passes-through INVPCID instruction
        // to guest if the instruction is supported.
        if !cpu_has_feature(X86_FEATURE_INVPCID) {
            set &= !SecondaryVmExecControls::INVPCID.bits();
        }

        // Disable pause-loop vmexit
        // Disable user wait/pause
        // Disable APICV features as vlapic starts from xapic mode
        let clear = (SecondaryVmExecControls::PAUSE_LOOP_EXITING
            | SecondaryVmExecControls::USR_WAIT_PAUSE
            | SecondaryVmExecControls::APIC_REGISTER_VIRT
            | SecondaryVmExecControls::VIRT_INTR_DELIVERY)
            .bits();

        let default = self.read32(VmcsField32Control::SECONDARY_VM_EXEC_CONTROL);
        let secondary_vmexec = VMCS_CAPS
            .check_vm_ctrl32(VmCtrlType32::SecondaryVmExec(VmCtrlCheck32 {
                default,
                set,
                clear,
            }))
            .unwrap();

        // TDX module may set VIRTUAL_X2APIC bit by default even TDP guest
        // vlapic starts from xapic mode, and this bit is read-only to L1 VMM.
        // If this is the case, set VIRTUAL_TRP in primary based VM execution
        // control. TPR is still emulated as the CR8 loading/restore vmexit bits
        // are also set.
        if secondary_vmexec & SecondaryVmExecControls::VIRTUAL_X2APIC.bits() != 0 {
            self.proc_vm_exec_ctrls |= PrimaryVmExecControls::VIRTUAL_TPR.bits();
        }

        // No feature needed in tertiary processor based VM execution controls
        self.write32(
            VmcsField32Control::PROC_BASED_VM_EXEC_CONTROL,
            self.proc_vm_exec_ctrls,
        );
        self.write32(
            VmcsField32Control::SECONDARY_VM_EXEC_CONTROL,
            secondary_vmexec,
        );

        if (secondary_vmexec & SecondaryVmExecControls::XSAVES.bits()) != 0 {
            self.write64(VmcsField64Control::XSS_EXIT_BITMAP, 0);
            self.xsave_enabled = true;
        }

        self.write32(VmcsField32Control::TPR_THRESHOLD, 0);

        // APIC-v, config APIC virtualized page address
        self.write64(
            VmcsField64Control::VIRTUAL_APIC_PAGE_ADDR,
            vlapic_page_pa.into(),
        );

        // Set up guest exception mask bitmap setting a bit * causes a VM exit
        // on corresponding guest * exception - pg 2902 24.6.3
        // enable VM exit on MC always
        self.write32(VmcsField32Control::EXCEPTION_BITMAP, 1u32 << MCE_VECTOR);

        // Set up page fault error code mask - second paragraph * pg 2902
        // 24.6.3 - guest page fault exception causing * vmexit is governed by
        // both VMX_EXCEPTION_BITMAP and * VMX_PF_ERROR_CODE_MASK
        self.write32(VmcsField32Control::PAGE_FAULT_ERROR_CODE_MASK, 0);

        // Set up page fault error code match - second paragraph * pg 2902
        // 24.6.3 - guest page fault exception causing * vmexit is governed by
        // both VMX_EXCEPTION_BITMAP and * VMX_PF_ERROR_CODE_MATCH
        self.write32(VmcsField32Control::PAGE_FAULT_ERROR_CODE_MATCH, 0);

        // Set up CR3 target count - An execution of mov to CR3 * by guest
        // causes HW to evaluate operand match with * one of N CR3-Target Value
        // registers. The CR3 target * count values tells the number of
        // target-value regs to evaluate
        self.write32(VmcsField32Control::CR3_TARGET_COUNT, 0);

        self.write64(
            VmcsField64Control::CR0_GUEST_HOST_MASK,
            get_cr0_guest_host_mask(),
        );
        self.write64(
            VmcsField64Control::CR4_GUEST_HOST_MASK,
            get_cr4_guest_host_mask(),
        );

        // The CR3 target registers work in concert with VMX_CR3_TARGET_COUNT
        // field. Using these registers guest CR3 access can be managed. i.e.,
        // if operand does not match one of these register values a VM exit
        // would occur
        self.write64(VmcsField64Control::CR3_TARGET_VALUE0, 0);
        self.write64(VmcsField64Control::CR3_TARGET_VALUE1, 0);
        self.write64(VmcsField64Control::CR3_TARGET_VALUE2, 0);
        self.write64(VmcsField64Control::CR3_TARGET_VALUE3, 0);
    }

    pub fn init_entry_ctrl(&self) {
        // All the bits in VM entry control are read-only except
        // for IA32E_MODE. TDP guest starts from real-mode. Make
        // sure this bit is cleared.
        let clear = VmEntryControls::IA32E_MODE.bits();
        self.write32(
            VmcsField32Control::VM_ENTRY_CONTROLS,
            VMCS_CAPS
                .check_vm_ctrl32(VmCtrlType32::VmEntryCtrl(VmCtrlCheck32 {
                    default: self.read32(VmcsField32Control::VM_ENTRY_CONTROLS),
                    set: 0,
                    clear,
                }))
                .unwrap(),
        );

        // Set up VM entry interrupt information field pg 2909 24.8.3
        self.write32(VmcsField32Control::VM_ENTRY_INTR_INFO_FIELD, 0);

        // Set up VM entry exception error code - pg 2910 24.8.3
        self.write32(VmcsField32Control::VM_ENTRY_EXCEPTION_ERROR_CODE, 0);

        // Set up VM entry instruction length - pg 2910 24.8.3
        self.write32(VmcsField32Control::VM_ENTRY_INSTRUCTION_LEN, 0);
    }

    pub fn init_exit_ctrl(&self) {
        // No need to set up VM exit controls as this field
        // is read-only to L1 VMM
    }

    pub fn init_guest_state(&self, pat_power_on_val: u64, dr7_init_value: u64) {
        // Guest Segment registers and CR registers are initialized
        // when loads GuestCpuContext before vmentry
        self.write32(VmcsField32Guest::SYSENTER_CS, 0);
        self.write64(VmcsField64Guest::SYSENTER_ESP, 0);
        self.write64(VmcsField64Guest::SYSENTER_EIP, 0);
        self.write64(VmcsField64Guest::PENDING_DBG_EXCEPTIONS, 0);
        self.write64(VmcsField64Guest::IA32_DEBUGCTL, 0);
        self.write32(VmcsField32Guest::INTERRUPTIBILITY_INFO, 0);
        self.write32(VmcsField32Guest::ACTIVITY_STATE, 0);
        self.write32(VmcsField32Guest::SMBASE, 0);
        self.write64(VmcsField64Guest::IA32_PAT, pat_power_on_val);
        self.write64(VmcsField64Guest::DR7, dr7_init_value);
    }

    pub fn enable_x2apic_virtualization(&mut self) {
        let mut secondary_vmexec = self.read32(VmcsField32Control::SECONDARY_VM_EXEC_CONTROL);
        assert!(
            VMCS_CAPS.allow_set_vm_ctrl32(VmCtrlType32::SecondaryVmExec(VmCtrlCheck32 {
                default: 0,
                set: (SecondaryVmExecControls::VIRTUAL_X2APIC
                    | SecondaryVmExecControls::APIC_REGISTER_VIRT
                    | SecondaryVmExecControls::VIRT_INTR_DELIVERY)
                    .bits(),
                clear: 0,
            }))
        );
        secondary_vmexec |= (SecondaryVmExecControls::VIRTUAL_X2APIC
            | SecondaryVmExecControls::APIC_REGISTER_VIRT
            | SecondaryVmExecControls::VIRT_INTR_DELIVERY)
            .bits();

        self.write32(
            VmcsField32Control::SECONDARY_VM_EXEC_CONTROL,
            secondary_vmexec,
        );

        // Disable CR8 interception.
        self.proc_vm_exec_ctrls &= !(PrimaryVmExecControls::CR8_LOAD_EXITING.bits()
            | PrimaryVmExecControls::CR8_STORE_EXITING.bits());
        // Make sure TPR shadow is enabled.
        self.proc_vm_exec_ctrls |= PrimaryVmExecControls::VIRTUAL_TPR.bits();

        self.write32(
            VmcsField32Control::PROC_BASED_VM_EXEC_CONTROL,
            self.proc_vm_exec_ctrls,
        );
    }
}

struct VmCtrlCheck32 {
    default: u32,
    set: u32,
    clear: u32,
}

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
