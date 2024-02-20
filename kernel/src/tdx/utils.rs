// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::error::TdxError;
use super::tdcall::{
    td_accept_memory, tdcall_vm_read, tdcall_vp_invept, tdcall_vp_invvpid, tdcall_vp_write,
    tdvmcall_mapgpa,
};
use crate::address::{Address, GuestPhysAddr};
use crate::types::PAGE_SIZE;
use bitflags::bitflags;

// According to TDP FAS 11.1 Introduction, a TD may contain up to 4 VMs.
// And one VM is primary VM (known as the L1 VM) and the other 3 are nested
// VMs(known as the L2 VMs).
pub const MAX_NUM_L2_VMS: usize = 3;
pub const FIRST_VM_ID: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TdpVmId {
    vm_id: u64,
}

impl TdpVmId {
    pub fn new(vm_id: u64) -> Result<Self, TdxError> {
        if (1..=MAX_NUM_L2_VMS as u64).contains(&vm_id) {
            Ok(TdpVmId { vm_id })
        } else {
            Err(TdxError::InvalidVmId(vm_id))
        }
    }

    pub fn index(&self) -> usize {
        (self.vm_id - 1) as usize
    }

    fn num(&self) -> u64 {
        self.vm_id
    }
}

const MD_TDCS_NUM_L2_VMS: u64 = 0x9010000100000005;
pub fn td_num_l2_vms() -> Result<u64, TdxError> {
    let num = tdcall_vm_read(MD_TDCS_NUM_L2_VMS).map_err(|_| TdxError::VmRD(MD_TDCS_NUM_L2_VMS))?;

    if (1..=MAX_NUM_L2_VMS as u64).contains(&num) {
        Ok(num)
    } else {
        Err(TdxError::TdpNotSupport)
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct L2CtlsFlags: u64 {
        const EnableSharedEPTP = 1 << 0;
        const EnableTdVmcall   = 1 << 1;
        const EnableExtedVE    = 1 << 2;
    }
}

const MD_TDVPS_L2_CTLS: u64 = 0xA020000300000050;
const MD_TDVPS_L2_CTLS_MASK: u64 = 0x7;
pub fn tdvps_l2_ctls(vm_id: TdpVmId, l2_ctls: L2CtlsFlags) -> Result<(), TdxError> {
    tdcall_vp_write(
        MD_TDVPS_L2_CTLS + vm_id.num(),
        l2_ctls.bits(),
        MD_TDVPS_L2_CTLS_MASK,
    )
    .map_err(|_| TdxError::VpWR(MD_TDVPS_L2_CTLS + vm_id.num(), l2_ctls.bits()))
}

pub const MD_CONTEXT_VP: u64 = 2;
const TDG_CLASS_SHIFT: u8 = 56;
const TDG_CLASS_MASK: u64 = 0x3f;
const TDG_CONTEXT_SHIFT: u8 = 52;
const TDG_CONTEXT_MASK: u64 = 0x7;
const TDG_WRITE_MASK_SHIFT: u8 = 51;
const TDG_ELEM_SIZE_SHIFT: u8 = 32;
const TDG_ELEM_SIZE_MASK: u64 = 0x3;
const TDG_FIELD_MASK: u64 = 0xffff_ffff;

const MD_TDVPS_VMCS_1_CLASS_CODE: u64 = 36;
const MD_TDVPS_MSR_BITMAPS_1_CLASS_CODE: u64 = 37;
pub enum TdVpsPerVmClass {
    Vmcs,
    MsrBitmap,
}

impl TdVpsPerVmClass {
    pub fn code(&self, vm_id: TdpVmId) -> u64 {
        let class_code = match self {
            TdVpsPerVmClass::Vmcs => MD_TDVPS_VMCS_1_CLASS_CODE,
            TdVpsPerVmClass::MsrBitmap => MD_TDVPS_MSR_BITMAPS_1_CLASS_CODE,
        };

        class_code + (vm_id.num() - 1) * 8
    }
}

pub fn field_elem_size(bits: u8) -> u64 {
    match bits {
        16 => 1u64,
        32 => 2u64,
        64 => 3u64,
        _ => {
            panic!("invalid bits {}", bits);
        }
    }
}

pub fn build_tdg_field(
    class: u64,
    context: u64,
    write_mask: u64,
    elem_size: u64,
    field: u64,
) -> u64 {
    assert!(
        class <= 0x3f
            && context <= 0x7
            && write_mask <= 1
            && elem_size <= 0x3
            && field <= 0xffff_ffff
    );
    ((class & TDG_CLASS_MASK) << TDG_CLASS_SHIFT)
        | ((context & TDG_CONTEXT_MASK) << TDG_CONTEXT_SHIFT)
        | (write_mask << TDG_WRITE_MASK_SHIFT)
        | ((elem_size & TDG_ELEM_SIZE_MASK) << TDG_ELEM_SIZE_SHIFT)
        | (field & TDG_FIELD_MASK)
}

pub fn td_convert_guest_pages(
    start: GuestPhysAddr,
    end: GuestPhysAddr,
    shared: bool,
) -> Result<usize, TdxError> {
    if !start.is_page_aligned() || !end.is_page_aligned() {
        return Err(TdxError::UnalignedPhysAddr);
    }

    let start_hpa = start.to_host_phys_addr();
    let end_hpa = end.to_host_phys_addr();

    // No need to strip the shared bit from GuestPhysAddr as tdvmcall_mapgpa
    // will do this according to the shared flag.
    tdvmcall_mapgpa(shared, start_hpa.into(), end_hpa - start_hpa).map_err(|e| {
        log::error!(
            "Convert guest memory 0x{:x} ~ 0x{:x} failed: {:?}",
            start,
            end,
            e
        );
        TdxError::MapGpa
    })?;

    if !shared {
        td_accept_memory(u64::from(start_hpa), (end_hpa - start_hpa) as u64);
    }

    Ok(end_hpa - start_hpa)
}

pub fn td_set_msr_bitmap(vm_id: TdpVmId, index: u32, val: u64, mask: u64) -> Result<(), TdxError> {
    let field = build_tdg_field(
        TdVpsPerVmClass::MsrBitmap.code(vm_id),
        MD_CONTEXT_VP,
        1,
        field_elem_size(64),
        u64::from(index),
    );

    tdcall_vp_write(field, val, mask).map_err(|e| {
        log::error!("Set MSR bitmap failed for MSR index 0x{:x}: {:?}", index, e);
        TdxError::VpWR(field, val)
    })
}

const VMX_VPID_TYPE_SINGLE_CONTEXT: u64 = 1;
const VMX_VPID_TYPE_ALL_CONTEXT: u64 = 2;

fn td_invvpid(vm_id: u64, type_id: u64, gva: u64) {
    if type_id != VMX_VPID_TYPE_SINGLE_CONTEXT {
        tdcall_vp_invept(1 << vm_id).expect("Failed to do invept");
    } else {
        tdcall_vp_invvpid(vm_id << 52, gva & !(PAGE_SIZE as u64 - 1))
            .expect("Failed to do invvpid");
    }
}

pub fn td_flush_vpid_global(vm_id: TdpVmId) {
    td_invvpid(vm_id.num(), VMX_VPID_TYPE_ALL_CONTEXT, 0);
}
