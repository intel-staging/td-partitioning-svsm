// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

extern crate alloc;

use super::vcr::get_cr4_reserved_mask;
use crate::cpu::control_regs::CR4Flags;
use crate::cpu::cpuid::{
    Cpuid06Eax, Cpuid06Ecx, Cpuid07_0Ebx, Cpuid07_0Ecx, Cpuid07_0Edx, Cpuid40000001Eax,
};
use alloc::collections::btree_map::BTreeMap;
use core::arch::x86_64::{CpuidResult, __cpuid_count};
use core::cmp::{Ord, Ordering};

#[derive(Clone, Copy, Debug)]
struct VcpuidKey {
    leaf: u32,
    // Make subleaf as option. If a leaf doesn't
    // have valid subleaf, then its subleaf in the
    // key is None. A value Some(0) represents a
    // valid subleaf 0
    subleaf: Option<u32>,
}

impl VcpuidKey {
    fn new(leaf: u32, subleaf: Option<u32>) -> Self {
        Self { leaf, subleaf }
    }
}

impl Ord for VcpuidKey {
    fn cmp(&self, other: &Self) -> Ordering {
        let ret = self.leaf.cmp(&other.leaf);
        match ret {
            Ordering::Equal => {
                // If the VcpuidKey's subleaf is none, means
                // there is no valid subleaf for this leaf.
                // So these two keys are equal if their leaf
                // are equal.
                if other.subleaf.is_none() {
                    Ordering::Equal
                } else {
                    self.subleaf.cmp(&other.subleaf)
                }
            }
            _ => ret,
        }
    }
}

impl PartialOrd for VcpuidKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for VcpuidKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for VcpuidKey {}

fn init_vcpuid_entry(leaf: u32, subleaf: Option<u32>) -> (VcpuidKey, CpuidResult) {
    let subleaf_val = if let Some(v) = subleaf { v } else { 0 };

    (
        VcpuidKey::new(leaf, subleaf),
        match leaf {
            0x00000007 => {
                if subleaf_val == 0 {
                    let cr4_reserved_mask = CR4Flags::from_bits_truncate(get_cr4_reserved_mask());

                    let mut val = unsafe { __cpuid_count(leaf, subleaf_val) };

                    // Mask CET SS and IBT
                    val.ecx &= !Cpuid07_0Ecx::CET_SS.bits();
                    val.edx &= !Cpuid07_0Edx::CET_IBT.bits();

                    if cr4_reserved_mask.contains(CR4Flags::FSGSBASE) {
                        val.ebx &= !Cpuid07_0Ebx::FSGSBASE.bits();
                    }

                    if cr4_reserved_mask.contains(CR4Flags::SMEP) {
                        val.ebx &= !Cpuid07_0Ebx::SMEP.bits();
                    }

                    if cr4_reserved_mask.contains(CR4Flags::SMAP) {
                        val.ebx &= !Cpuid07_0Ebx::SMAP.bits();
                    }

                    if cr4_reserved_mask.contains(CR4Flags::UMIP) {
                        val.ecx &= !Cpuid07_0Ecx::UMIP.bits();
                    }

                    if cr4_reserved_mask.contains(CR4Flags::PKE) {
                        val.ecx &= !Cpuid07_0Ecx::PKU.bits();
                    }

                    if cr4_reserved_mask.contains(CR4Flags::LA57) {
                        val.ecx &= !Cpuid07_0Ecx::LA57.bits();
                    }

                    if cr4_reserved_mask.contains(CR4Flags::PKS) {
                        val.ecx &= !Cpuid07_0Ecx::PKS.bits();
                    }
                    val
                } else {
                    unsafe { __cpuid_count(leaf, subleaf_val) }
                }
            }
            0x00000021 => {
                // Signature "IntelTDP    "
                let ebx = u32::from_le_bytes([b'I', b'n', b't', b'e']);
                let edx = u32::from_le_bytes([b'l', b'T', b'D', b'P']);
                let ecx = u32::from_le_bytes([b' ', b' ', b' ', b' ']);

                CpuidResult {
                    eax: 0,
                    ebx,
                    ecx,
                    edx,
                }
            }
            0x40000001 => {
                let mut val = unsafe { __cpuid_count(leaf, subleaf_val) };
                // Mask KVM_FEATURE_PV_SEND_IPI
                val.eax &= !Cpuid40000001Eax::KVM_FEATURE_PV_SEND_IPI.bits();
                val
            }
            _ => unsafe { __cpuid_count(leaf, subleaf_val) },
        },
    )
}

#[derive(Debug)]
pub struct Vcpuid {
    entries: BTreeMap<VcpuidKey, CpuidResult>,
    vcpuid_level: u32,
    vcpuid_xlevel: u32,
}

fn is_percpu_related(leaf: u32) -> bool {
    matches!(
        leaf,
        0x00000001 | 0x00000002 | 0x0000000b | 0x0000000d | 0x00000019 | 0x0000001a | 0x80000001
    )
}

impl Vcpuid {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            vcpuid_level: 0,
            vcpuid_xlevel: 0,
        }
    }

    pub fn init(&mut self) {
        let entries = &mut self.entries;

        let (key, entry) = init_vcpuid_entry(0, None);
        entries.insert(key, entry);
        self.vcpuid_level = entry.eax;

        for leaf in 1..=self.vcpuid_level {
            if is_percpu_related(leaf) {
                continue;
            }
            match leaf {
                0x00000004 => {
                    let mut subleaf = 0;
                    loop {
                        let (key, entry) = init_vcpuid_entry(leaf, Some(subleaf));

                        if entry.eax == 0 {
                            break;
                        }
                        entries.insert(key, entry);
                        subleaf += 1;
                    }
                }
                0x00000006 => {
                    let (key, mut entry) = init_vcpuid_entry(leaf, Some(0));
                    entry.eax &= !Cpuid06Eax::HWP.bits();
                    entry.ecx &= !Cpuid06Ecx::HCF.bits();
                    entries.insert(key, entry);
                }
                0x00000007 => {
                    let (key, mut entry) = init_vcpuid_entry(leaf, Some(0));

                    if entry.eax != 0 {
                        log::info!("Only support subleaf 0 for leaf 07h");
                        entry.eax = 0;
                    }
                    entry.ebx |= Cpuid07_0Ebx::TSC_ADJUST.bits();
                    entry.ecx &= !Cpuid07_0Ecx::WAITPKG.bits();
                    entries.insert(key, entry);
                }
                // Not supported CPU leaives are not saved into entries
                0x00000005 => continue,
                0x0000000a => continue,
                0x0000000f => continue,
                0x00000010 => continue,
                0x00000014 => continue,
                0x0000001b => continue,
                0x0000001f => continue,
                // The other CPU leavies are just reuse L1's VCPUID
                _ => {
                    let (key, entry) = init_vcpuid_entry(leaf, None);
                    entries.insert(key, entry);
                }
            }
        }

        let (key, entry) = init_vcpuid_entry(0x40000000, None);
        entries.insert(key, entry);
        let last_leaf = entry.eax;

        let (key, entry) = init_vcpuid_entry(0x40000001, None);
        entries.insert(key, entry);

        if last_leaf >= 0x40000010 {
            let (key, entry) = init_vcpuid_entry(0x40000010, None);
            entries.insert(key, entry);
        }

        let (key, entry) = init_vcpuid_entry(0x80000000, None);
        entries.insert(key, entry);
        self.vcpuid_xlevel = entry.eax;

        for leaf in 0x80000002..=self.vcpuid_xlevel {
            let (key, entry) = init_vcpuid_entry(leaf, None);
            entries.insert(key, entry);
        }
    }
}
