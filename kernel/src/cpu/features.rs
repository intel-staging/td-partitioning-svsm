// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::cpuid::{cpuid, Cpuid01Edx, Cpuid80000001Edx};
use lazy_static::lazy_static;

// CPUID level 0x00000001 (EDX), word 0
pub const X86_FEATURE_PGE: u32 = Cpuid01Edx::PGE.bits().trailing_zeros();
// CPUID level 0x80000001 (EDX), word 1
pub const X86_FEATURE_NX: u32 = 32 + Cpuid80000001Edx::NX.bits().trailing_zeros();

const FEATURE_WORDS: usize = 2;

struct X86Features {
    word: [u32; FEATURE_WORDS],
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

        X86Features { word }
    }
}

lazy_static! {
    static ref X86_FEATURES: X86Features = X86Features::new();
}

pub fn cpu_has_feature(feat: u32) -> bool {
    X86_FEATURES.word[(feat / 32) as usize] & (feat % 32) != 0
}
