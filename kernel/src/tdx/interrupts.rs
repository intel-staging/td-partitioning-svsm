// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use crate::cpu::idt::common::X86ExceptionContext;
use crate::cpu::interrupts::register_interrupt_handler;
use crate::error::SvsmError;

const FIXED_VECTOR_START: u8 = 0xE0;

pub const TIMER_VECTOR: u8 = FIXED_VECTOR_START;
pub const VCPU_KICK_VECTOR: u8 = FIXED_VECTOR_START + 1;

fn handle_vcpu_kick(_ctx: &X86ExceptionContext) {
    // No need to do anything
}

fn handle_timer(_ctx: &X86ExceptionContext) {
    //TODO: handle timer interrupts
}

pub fn register_interrupt_handlers() -> Result<(), SvsmError> {
    register_interrupt_handler(Some(VCPU_KICK_VECTOR), handle_vcpu_kick)
        .map(|_| ())
        .map_err(SvsmError::Irq)?;
    register_interrupt_handler(Some(TIMER_VECTOR), handle_timer)
        .map(|_| ())
        .map_err(SvsmError::Irq)
}
