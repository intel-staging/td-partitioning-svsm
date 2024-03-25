// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::cpuid::{cpuid, Cpuid01Ecx, Cpuid01Edx, Cpuid07_0Ebx, Cpuid80000001Edx};
use crate::types::CpuType;
use lazy_static::lazy_static;

// CPUID level 0x00000001 (EDX), word 0
pub const X86_FEATURE_PGE: u32 = Cpuid01Edx::PGE.bits().trailing_zeros();
// CPUID level 0x80000001 (EDX), word 1
pub const X86_FEATURE_NX: u32 = 32 + Cpuid80000001Edx::NX.bits().trailing_zeros();
// CPUID level 0x00000001 (ECX), word 2
pub const X86_FEATURE_X2APIC: u32 = 2 * 32 + Cpuid01Ecx::X2APIC.bits().trailing_zeros();
pub const X86_FEATURE_XSAVE: u32 = 2 * 32 + Cpuid01Ecx::XSAVE.bits().trailing_zeros();
// CPUID level 0x00000007:0 (EBX), word 3
pub const X86_FEATURE_INVPCID: u32 = 3 * 32 + Cpuid07_0Ebx::INVPCID.bits().trailing_zeros();

const FEATURE_WORDS: usize = 4;

struct X86Features {
    word: [u32; FEATURE_WORDS],
    xcr0: u64,
}

impl X86Features {
    fn new() -> Self {
        let mut word = [0; FEATURE_WORDS];
        // Word 0 contains CPUID level 0x00000001 EDX
        let cpuid01 = cpuid(0x00000001).unwrap();
        word[0] = cpuid01.edx;
        // Word 1 contains CPUID level 0x80000001 EDX
        let cpuid80000001 = cpuid(0x80000001).unwrap();
        word[1] = cpuid80000001.edx;
        // Word 2 contains CPUID level 0x00000001 ECX
        word[2] = cpuid01.ecx;
        // Word 3 contains CPUID level 0x00000007:0 EBX
        let cpuid07_0 = cpuid(0x00000007).unwrap();
        word[3] = cpuid07_0.ebx;

        let cpuid0d_0 = cpuid(0x0000000d).unwrap();
        let xcr0 = cpuid0d_0.eax as u64 | ((cpuid0d_0.edx as u64) << 32);

        X86Features { word, xcr0 }
    }
}

lazy_static! {
    static ref X86_FEATURES: X86Features = X86Features::new();
}

pub fn cpu_has_feature(feat: u32) -> bool {
    X86_FEATURES.word[(feat / 32) as usize] & (1u32 << (feat % 32)) != 0
}

pub fn cpu_has_xcr0_features(feats: u64) -> bool {
    (X86_FEATURES.xcr0 & feats) == feats
}

fn is_td_cpu() -> bool {
    let ret = cpuid(0x00000000);
    match ret {
        None => {
            return false;
        }
        Some(c) => {
            if c.ebx != 0x756e6547 || c.edx != 0x49656e69 || c.ecx != 0x6c65746e {
                return false;
            }
        }
    }

    let ret = cpuid(0x00000001);
    match ret {
        None => {
            return false;
        }
        Some(c) => {
            if c.ecx & 0x80000000 == 0 {
                return false;
            }
        }
    }

    let ret = cpuid(0x00000021);
    match ret {
        None => {
            return false;
        }
        Some(c) => {
            if c.ebx != 0x65746e49 || c.edx != 0x5844546c || c.ecx != 0x20202020 {
                return false;
            }
        }
    }

    true
}

fn get_cpu_type() -> CpuType {
    if is_td_cpu() {
        CpuType::Td
    } else {
        CpuType::Sev
    }
}

lazy_static! {
    static ref CPU_TYPE: CpuType = get_cpu_type();
}

pub fn cpu_type() -> CpuType {
    *CPU_TYPE
}

pub fn is_sev() -> bool {
    cpu_type() == CpuType::Sev
}

pub fn is_tdx() -> bool {
    cpu_type() == CpuType::Td
}

pub fn cpu_max_physaddr_bits() -> u8 {
    let ret = cpuid(0x80000008);

    match ret {
        None => 0,
        Some(c) => c.eax as u8,
    }
}
