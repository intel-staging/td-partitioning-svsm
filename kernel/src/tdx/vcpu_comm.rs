// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use bitflags::bitflags;
use core::sync::atomic::{AtomicU64, Ordering};

bitflags! {
    // Vcpu request flag bits.
    pub struct VcpuReqFlags: u64 {
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct VcpuCommBlock {
    apic_id: u32,
    pending_req: AtomicU64,
}

#[allow(dead_code)]
impl VcpuCommBlock {
    pub fn new(apic_id: u32) -> Self {
        Self {
            apic_id,
            pending_req: AtomicU64::new(0),
        }
    }

    pub fn make_request(&self, req: VcpuReqFlags) {
        self.pending_req.fetch_or(req.bits(), Ordering::AcqRel);
    }

    pub fn test_and_clear_request(&self, req: VcpuReqFlags) -> bool {
        let mask = req.bits();
        (self.pending_req.fetch_and(!mask, Ordering::AcqRel) & mask) != 0
    }

    pub fn has_request(&self, req: VcpuReqFlags) -> bool {
        (self.pending_req.load(Ordering::Acquire) & req.bits()) != 0
    }

    pub fn clear_request(&self, req: VcpuReqFlags) {
        let mask = req.bits();
        self.pending_req.fetch_and(!mask, Ordering::Acquire);
    }

    pub fn is_request_empty(&self) -> bool {
        self.pending_req.load(Ordering::Acquire) == 0
    }
}
