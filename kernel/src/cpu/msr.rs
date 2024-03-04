// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::error::SvsmError;
use bitflags::bitflags;
use core::arch::asm;

pub const MSR_IA32_TIME_STAMP_COUNTER: u32 = 0x0000_0010;
pub const MSR_IA32_PLATFORM_ID: u32 = 0x0000_0017;
pub const MSR_IA32_APIC_BASE: u32 = 0x0000_001B;
pub const MSR_SMI_COUNT: u32 = 0x0000_0034;
pub const MSR_IA32_FEATURE_CONTROL: u32 = 0x0000_003A;
pub const MSR_IA32_TSC_ADJUST: u32 = 0x0000_003B;
pub const MSR_IA32_SPEC_CTRL: u32 = 0x0000_0048;
pub const MSR_IA32_PRED_CMD: u32 = 0x0000_0049;
pub const MSR_IA32_BIOS_UPDT_TRIG: u32 = 0x0000_0079;
pub const MSR_IA32_BIOS_SIGN_ID: u32 = 0x0000_008B;
pub const MSR_PLATFORM_INFO: u32 = 0x0000_00CE;
pub const MSR_IA32_UMWAIT_CONTROL: u32 = 0x0000_00E1;
pub const MSR_IA32_MTRR_CAP: u32 = 0x0000_00FE;
pub const MSR_IA32_ARCH_CAPABILITIES: u32 = 0x0000_010A;
pub const MSR_MISC_FEATURE_ENABLES: u32 = 0x0000_0140;
pub const MSR_IA32_SYSENTER_CS: u32 = 0x0000_0174;
pub const MSR_IA32_SYSENTER_ESP: u32 = 0x0000_0175;
pub const MSR_IA32_SYSENTER_EIP: u32 = 0x0000_0176;
pub const MSR_IA32_MCG_CAP: u32 = 0x0000_0179;
pub const MSR_IA32_MCG_STATUS: u32 = 0x0000_017A;
pub const MSR_IA32_PERF_STATUS: u32 = 0x0000_0198;
pub const MSR_IA32_PERF_CTL: u32 = 0x0000_0199;
pub const MSR_IA32_MISC_ENABLE: u32 = 0x0000_01A0;
pub const MSR_IA32_XFD: u32 = 0x0000_01C4;
pub const MSR_IA32_DEBUGCTL: u32 = 0x0000_01D9;
pub const MSR_IA32_PAT: u32 = 0x0000_0277;
pub const MSR_IA32_MTRR_DEF_TYPE: u32 = 0x0000_02FF;
pub const MSR_IA32_VMX_CR0_FIXED0: u32 = 0x0000_0486;
pub const MSR_IA32_VMX_CR0_FIXED1: u32 = 0x0000_0487;
pub const MSR_IA32_VMX_CR4_FIXED0: u32 = 0x0000_0488;
pub const MSR_IA32_VMX_CR4_FIXED1: u32 = 0x0000_0489;
pub const MSR_VMX_PROCBASED_CTLS2: u32 = 0x0000_048B;
pub const MSR_VMX_TRUE_PROCBASED_CTLS: u32 = 0x0000_048E;
pub const MSR_VMX_TRUE_ENTRY_CTLS: u32 = 0x0000_0490;
pub const MSR_IA32_TSC_DEADLINE: u32 = 0x0000_06E0;

// MTRR Range Registers
pub const MSR_IA32_MTRR_RANGE_FIRST: u32 = 0x0000_0200;
pub const MSR_IA32_MTRR_RANGE_LAST: u32 = 0x0000_026F;

// x2APIC Registers
pub const MSR_IA32_EXT_APIC_FIRST: u32 = 0x0000_0800;
pub const MSR_IA32_EXT_APIC_TPR: u32 = 0x0000_0808;
pub const MSR_IA32_EXT_APIC_EOI: u32 = 0x0000_080B;
pub const MSR_IA32_EXT_APIC_CUR_COUNT: u32 = 0x0000_0839;
pub const MSR_IA32_EXT_APIC_SELF_IPI: u32 = 0x0000_083F;
pub const MSR_IA32_EXT_APIC_LAST: u32 = 0x0000_08FF;

pub const MSR_IA32_XSS: u32 = 0x0000_0DA0;

pub const EFER: u32 = 0xC000_0080;
pub const MSR_IA32_STAR: u32 = 0xC000_0081;
pub const MSR_IA32_LSTAR: u32 = 0xC000_0082;
pub const MSR_IA32_CSTAR: u32 = 0xC000_0083;
pub const MSR_IA32_FMASK: u32 = 0xC000_0084;
pub const MSR_IA32_FS_BASE: u32 = 0xC000_0100;
pub const MSR_IA32_GS_BASE: u32 = 0xC000_0101;
pub const MSR_IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;
pub const MSR_IA32_TSC_AUX: u32 = 0xC000_0103;
pub const SEV_STATUS: u32 = 0xC001_0131;
pub const SEV_GHCB: u32 = 0xC001_0130;
pub const MSR_GS_BASE: u32 = 0xC000_0101;

const PAT_MEM_TYPE_UNCACHEABLE: u64 = 0x0;
const PAT_MEM_TYPE_WRITE_THROUGH: u64 = 0x4;
const PAT_MEM_TYPE_WRITE_BACK: u64 = 0x6;
const PAT_MEM_TYPE_UNCACHED: u64 = 0x7;

pub const PAT_POWER_ON_VALUE: u64 = PAT_MEM_TYPE_WRITE_BACK
    + (PAT_MEM_TYPE_WRITE_THROUGH << 8)
    + (PAT_MEM_TYPE_UNCACHED << 16)
    + (PAT_MEM_TYPE_UNCACHEABLE << 24)
    + (PAT_MEM_TYPE_WRITE_BACK << 32)
    + (PAT_MEM_TYPE_WRITE_THROUGH << 40)
    + (PAT_MEM_TYPE_UNCACHED << 48)
    + (PAT_MEM_TYPE_UNCACHEABLE << 56);

pub const PAT_ALL_UC_VALUE: u64 = PAT_MEM_TYPE_UNCACHEABLE
    + (PAT_MEM_TYPE_UNCACHEABLE << 8)
    + (PAT_MEM_TYPE_UNCACHEABLE << 16)
    + (PAT_MEM_TYPE_UNCACHEABLE << 24)
    + (PAT_MEM_TYPE_UNCACHEABLE << 32)
    + (PAT_MEM_TYPE_UNCACHEABLE << 40)
    + (PAT_MEM_TYPE_UNCACHEABLE << 48)
    + (PAT_MEM_TYPE_UNCACHEABLE << 56);

bitflags! {
    pub struct MsrIa32FeatureControl: u64 {
        const LOCK          = 1 << 0;
    }
}

bitflags! {
    #[derive(Debug)]
    pub struct MsrIa32MiscEnable: u64 {
        const EN_EIST       = 1 << 16;
        const EN_MONITOR    = 1 << 18;
        const LIMIT_CPUID   = 1 << 22;
        const XD_DISABLE    = 1 << 34;
    }
}

pub fn read_msr(msr: u32) -> Result<u64, SvsmError> {
    let eax: u32;
    let edx: u32;
    let rcx: u64;

    unsafe {
        asm!("1: rdmsr",
             "   xorq %rcx, %rcx",
             "2:",
             ".pushsection \"__exception_table\",\"a\"",
             ".balign 16",
             ".quad (1b)",
             ".quad (2b)",
             ".popsection",
                in("ecx") msr,
                out("eax") eax,
                out("edx") edx,
                lateout("rcx") rcx,
                options(att_syntax, nostack));
    }

    if rcx == 0 {
        let ret = (eax as u64) | (edx as u64) << 32;
        Ok(ret)
    } else {
        Err(SvsmError::Msr)
    }
}

pub fn write_msr(msr: u32, val: u64) -> Result<(), SvsmError> {
    let eax = val as u32;
    let edx = (val >> 32) as u32;
    let rcx: u64;

    unsafe {
        asm!("1: wrmsr",
             "   xorq %rcx, %rcx",
             "2:",
             ".pushsection \"__exception_table\",\"a\"",
             ".balign 16",
             ".quad (1b)",
             ".quad (2b)",
             ".popsection",
                in("ecx") msr,
                in("eax") eax,
                in("edx") edx,
                lateout("rcx") rcx,
                options(att_syntax, nostack));
    }

    if rcx == 0 {
        Ok(())
    } else {
        Err(SvsmError::Msr)
    }
}

pub fn rdtsc() -> u64 {
    let eax: u32;
    let edx: u32;

    unsafe {
        asm!("rdtsc",
             out("eax") eax,
             out("edx") edx,
             options(att_syntax, nomem, nostack));
    }
    (eax as u64) | (edx as u64) << 32
}

pub fn read_flags() -> u64 {
    let rax: u64;
    unsafe {
        asm!(
            r#"
                pushfq
                pop     %rax
            "#,
             out("rax") rax,
             options(att_syntax));
    }
    rax
}
