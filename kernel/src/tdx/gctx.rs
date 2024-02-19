// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

use super::utils::TdpVmId;
use crate::address::VirtAddr;
use crate::mm::address_space::virt_to_phys;

#[allow(dead_code)]
#[derive(Copy, Clone, Default)]
struct GuestCpuGPRegs {
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

#[repr(C)]
#[repr(align(256))]
#[derive(Clone, Copy, Default)]
struct GuestCpuTdpContext {
    gpregs: GuestCpuGPRegs,
    rflags: u64,
    rip: u64,
    ssp: u64,
    intr_status: u16,
}

const REAL_MODE_RIP: u64 = 0xfff0;
const REAL_MODE_RFLAGS: u64 = 0x02;

pub struct GuestCpuContext {
    vm_id: TdpVmId,
    tdp_ctx: GuestCpuTdpContext,
    tdp_ctx_pa: u64,
}

impl GuestCpuContext {
    pub fn init(&mut self, vm_id: TdpVmId) {
        self.vm_id = vm_id;
        self.tdp_ctx_pa = u64::from(virt_to_phys(VirtAddr::from(core::ptr::addr_of!(
            self.tdp_ctx
        ))));
    }

    pub fn reset(&mut self) {
        self.tdp_ctx = GuestCpuTdpContext::default();
        self.tdp_ctx.rip = REAL_MODE_RIP;
        self.tdp_ctx.rflags = REAL_MODE_RFLAGS;
    }
}
