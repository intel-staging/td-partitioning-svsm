// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

extern crate alloc;

use super::percpu::this_vcpu;
use super::utils::TdpVmId;
use super::vcr::get_cr4_reserved_mask;
use crate::cpu::control_regs::{read_cr4, CR4Flags};
use crate::cpu::cpuid::{
    Cpuid01Ecx, Cpuid01Edx, Cpuid06Eax, Cpuid06Ecx, Cpuid07_0Ebx, Cpuid07_0Ecx, Cpuid07_0Edx,
    Cpuid40000001Eax, Cpuid80000001Edx, CPUID01_EBX_APICID_MASK, CPUID01_EBX_APICID_SHIFT,
};
use crate::cpu::msr::{MsrIa32MiscEnable, MSR_IA32_MISC_ENABLE};
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
    vm_id: TdpVmId,
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
    pub fn new(vm_id: TdpVmId) -> Self {
        Self {
            vm_id,
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

    fn lookup_vcpuid_entries(&self, leaf: u32, subleaf: u32) -> Option<&CpuidResult> {
        let key = VcpuidKey::new(leaf, Some(subleaf));
        self.entries.get(&key)
    }

    fn find_vcpuid_entry(&self, leaf: u32, subleaf: u32) -> Option<&CpuidResult> {
        self.lookup_vcpuid_entries(leaf, subleaf).map_or_else(
            || {
                let limit = if (leaf & 0x80000000) != 0 {
                    self.vcpuid_xlevel
                } else {
                    self.vcpuid_level
                };

                //SDM Vol. 2A - Instruction Set Reference - CPUID
                //If a value entered for CPUID.EAX is higher than
                //the maximum input value for basic or extended
                //function for that processor then the data for the
                //highest basic information leaf is returned
                if leaf > limit {
                    self.lookup_vcpuid_entries(self.vcpuid_level, subleaf)
                } else {
                    None
                }
            },
            Some,
        )
    }

    fn get_vcpuid_01h(&self, subleaf: u32) -> Option<CpuidResult> {
        let cr4_reserved_mask = CR4Flags::from_bits_truncate(get_cr4_reserved_mask());
        let mut vcpuid = unsafe { __cpuid_count(0x00000001, subleaf) };

        // Patch with XAPIC ID
        let apicid = this_vcpu(self.vm_id).get_vlapic().apic_id();
        vcpuid.ebx &= !CPUID01_EBX_APICID_MASK;
        vcpuid.ebx |= apicid << CPUID01_EBX_APICID_SHIFT;

        if (vcpuid.ecx & Cpuid01Ecx::XSAVE.bits()) != 0
            && (this_vcpu(self.vm_id).get_ctx().get_cr4() & CR4Flags::OSXSAVE.bits()) != 0
        {
            vcpuid.ecx |= Cpuid01Ecx::OSXSAVE.bits();
        }

        // Mask SDBG for silicon debug
        vcpuid.ecx &= !Cpuid01Ecx::SDBG.bits();
        // Mask PDCM: Perfmon and Debug Capability
        vcpuid.ecx &= !Cpuid01Ecx::PDCM.bits();

        // Mask Debug Store
        vcpuid.ecx &= !(Cpuid01Ecx::DTES64 | Cpuid01Ecx::DS_CPL).bits();
        vcpuid.edx &= !Cpuid01Edx::DTES.bits();

        let misc = MsrIa32MiscEnable::from_bits_truncate(
            this_vcpu(self.vm_id)
                .get_ctx()
                .get_msrs()
                .read(MSR_IA32_MISC_ENABLE)
                .unwrap(),
        );
        if !misc.contains(MsrIa32MiscEnable::EN_EIST) {
            vcpuid.ecx &= !Cpuid01Ecx::EIST.bits();
        }

        if cr4_reserved_mask.contains(CR4Flags::PCIDE) {
            vcpuid.ecx &= !Cpuid01Ecx::PCID.bits();
        }

        if cr4_reserved_mask.contains(CR4Flags::VME) {
            vcpuid.edx &= !Cpuid01Edx::VME.bits();
        }

        if cr4_reserved_mask.contains(CR4Flags::DE) {
            vcpuid.edx &= !Cpuid01Edx::DE.bits();
        }

        if cr4_reserved_mask.contains(CR4Flags::PSE) {
            vcpuid.edx &= !Cpuid01Edx::PSE.bits();
        }

        if cr4_reserved_mask.contains(CR4Flags::PAE) {
            vcpuid.edx &= !Cpuid01Edx::PAE.bits();
        }

        if cr4_reserved_mask.contains(CR4Flags::PGE) {
            vcpuid.edx &= !Cpuid01Edx::PGE.bits();
        }

        if cr4_reserved_mask.contains(CR4Flags::OSFXSR) {
            vcpuid.edx &= !Cpuid01Edx::FXSR.bits();
        }

        Some(vcpuid)
    }

    fn get_vcpuid_0bh(&self, subleaf: u32) -> Option<CpuidResult> {
        let mut vcpuid = unsafe { __cpuid_count(0x0000000b, subleaf) };

        // Patch with X2APIC ID
        vcpuid.edx = this_vcpu(self.vm_id).get_vlapic().apic_id();

        Some(vcpuid)
    }

    fn get_vcpuid_0dh(&self, subleaf: u32) -> Option<CpuidResult> {
        let cr4 = read_cr4();
        if cr4.contains(CR4Flags::OSXSAVE) {
            Some(unsafe { __cpuid_count(0x0000000d, subleaf) })
        } else {
            None
        }
    }

    fn get_vcpuid_19h(&self, _subleaf: u32) -> Option<CpuidResult> {
        // Not support
        None
    }

    fn get_vcpuid_80000001h(&self, subleaf: u32) -> Option<CpuidResult> {
        if let Some(e) = self.find_vcpuid_entry(0x80000000, subleaf) {
            if e.eax >= 0x80000001 {
                let mut vcpuid = unsafe { __cpuid_count(0x80000001, subleaf) };
                let vmsr = MsrIa32MiscEnable::from_bits_truncate(
                    this_vcpu(self.vm_id)
                        .get_ctx()
                        .get_msrs()
                        .read(MSR_IA32_MISC_ENABLE)
                        .unwrap(),
                );
                if vmsr.contains(MsrIa32MiscEnable::XD_DISABLE) {
                    vcpuid.edx &= !Cpuid80000001Edx::NX.bits();
                }
                Some(vcpuid)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn limit_vcpuid(&self, leaf: u32, src: CpuidResult) -> CpuidResult {
        let vmsr = MsrIa32MiscEnable::from_bits_truncate(
            this_vcpu(self.vm_id)
                .get_ctx()
                .get_msrs()
                .read(MSR_IA32_MISC_ENABLE)
                .unwrap(),
        );
        let mut vcpuid = src;

        if vmsr.contains(MsrIa32MiscEnable::LIMIT_CPUID) {
            if leaf == 0x00000000 {
                vcpuid.eax = 2;
            } else if leaf > 0x00000002 {
                vcpuid.eax = 0;
                vcpuid.ebx = 0;
                vcpuid.ecx = 0;
                vcpuid.edx = 0;
            }
        }

        vcpuid
    }

    pub fn get(&self, leaf: u32, subleaf: u32) -> CpuidResult {
        let cpuid = if is_percpu_related(leaf) {
            match leaf {
                0x00000001 => self.get_vcpuid_01h(subleaf),
                0x0000000b => self.get_vcpuid_0bh(subleaf),
                0x0000000d => self.get_vcpuid_0dh(subleaf),
                0x00000019 => self.get_vcpuid_19h(subleaf),
                0x80000001 => self.get_vcpuid_80000001h(subleaf),
                _ => Some(unsafe { __cpuid_count(leaf, subleaf) }),
            }
        } else {
            self.find_vcpuid_entry(leaf, subleaf).copied()
        };

        if let Some(v) = cpuid {
            self.limit_vcpuid(leaf, v)
        } else {
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            }
        }
    }
}
