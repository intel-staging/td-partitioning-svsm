// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use core::arch::asm;

pub fn enable_irq() {
    unsafe { asm!("sti") };
}
