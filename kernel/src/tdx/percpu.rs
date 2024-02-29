// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use crate::cpu::percpu::PerCpuArch;
use core::any::Any;

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct TdPerCpu {
    apic_id: u32,
    is_bsp: bool,
}
unsafe impl Send for TdPerCpu {}
unsafe impl Sync for TdPerCpu {}

impl PerCpuArch for TdPerCpu {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl TdPerCpu {
    pub fn new(apic_id: u32, is_bsp: bool) -> Self {
        Self { apic_id, is_bsp }
    }
}
