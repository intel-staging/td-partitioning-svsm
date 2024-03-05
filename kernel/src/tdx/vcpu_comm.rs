// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

extern crate alloc;

use super::vcpu::{kick_vcpu, VcpuState};
use super::vlapic::VlapicRegsRead;
use crate::locking::SpinLock;
use alloc::collections::vec_deque::VecDeque;
use alloc::sync::Arc;
use bitflags::bitflags;
use core::sync::atomic::{AtomicU64, Ordering};

bitflags! {
    // Vcpu request flag bits.
    pub struct VcpuReqFlags: u64 {
        const EN_X2APICV        = 1 << 0;
        const VTIMER            = 1 << 1;
        const SIRTE             = 1 << 2;
        const INJ_NMI           = 1 << 3;
        const REQ_EVENT         = 1 << 4;
        const INJ_EXCP          = 1 << 5;
        const TRPFAULT          = 1 << 6;
        const DIS_IRQWIN        = 1 << 7;
        const FLUSH_EPT         = 1 << 8;
    }
}

pub enum VcpuStateReq {
    Init,
    Sipi { entry: u64 },
}

#[derive(Debug)]
pub struct VcpuCommBlock {
    pub apic_id: u32,
    pub vlapic: Arc<dyn VlapicRegsRead>,
    pending_req: AtomicU64,
    pending_state: SpinLock<VecDeque<VcpuState>>,
}

impl VcpuCommBlock {
    pub fn new(apic_id: u32, vlapic: Arc<dyn VlapicRegsRead>) -> Self {
        Self {
            apic_id,
            vlapic,
            pending_req: AtomicU64::new(0),
            pending_state: SpinLock::new(VecDeque::new()),
        }
    }

    pub fn make_request(&self, req: VcpuReqFlags) {
        self.pending_req.fetch_or(req.bits(), Ordering::AcqRel);
        kick_vcpu(self.apic_id);
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

    pub fn make_pending_state(&self, req: VcpuStateReq) {
        match req {
            VcpuStateReq::Init => {
                let mut pending_state = self.pending_state.lock();
                pending_state.push_back(VcpuState::Zombie);
                pending_state.push_back(VcpuState::InitKicked);
            }
            VcpuStateReq::Sipi { entry } => {
                let mut pending_state = self.pending_state.lock();
                pending_state.push_back(VcpuState::SipiKicked(entry));
            }
        }

        kick_vcpu(self.apic_id);
    }

    pub fn get_pending_state(&self) -> Option<VcpuState> {
        self.pending_state.lock().pop_front()
    }
}
