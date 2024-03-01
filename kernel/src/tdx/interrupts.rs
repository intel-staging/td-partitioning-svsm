// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::tdp::get_vcpu_cb;
use super::utils::{TdpVmId, FIRST_VM_ID};
use super::vcpu_comm::VcpuReqFlags;
use crate::cpu::idt::common::X86ExceptionContext;
use crate::cpu::interrupts::register_interrupt_handler;
use crate::cpu::lapic::LAPIC;
use crate::error::SvsmError;

const FIXED_VECTOR_START: u8 = 0xE0;

pub const TIMER_VECTOR: u8 = FIXED_VECTOR_START;
pub const VCPU_KICK_VECTOR: u8 = FIXED_VECTOR_START + 1;

fn handle_vcpu_kick(_ctx: &X86ExceptionContext) {
    // No need to do anything
}

fn handle_timer(_ctx: &X86ExceptionContext) {
    // Currently only support running one single TDP guest so always
    // assumes the timer interrupts are for TDP vlapic to emulate
    // timer.
    let vm_id = TdpVmId::new(FIRST_VM_ID).unwrap();
    if let Some(cb) = get_vcpu_cb(vm_id, LAPIC.id()) {
        cb.make_request(VcpuReqFlags::VTIMER);
    }
}

pub fn register_interrupt_handlers() -> Result<(), SvsmError> {
    register_interrupt_handler(Some(VCPU_KICK_VECTOR), handle_vcpu_kick)
        .map(|_| ())
        .map_err(SvsmError::Irq)?;
    register_interrupt_handler(Some(TIMER_VECTOR), handle_timer)
        .map(|_| ())
        .map_err(SvsmError::Irq)
}
