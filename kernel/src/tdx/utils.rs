// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::error::TdxError;
use super::tdcall::tdcall_vm_read;

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
