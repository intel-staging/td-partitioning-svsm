// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::idt::common::{X86ExceptionContext, IDT_ENTRIES};
use super::lapic::LAPIC;
use crate::locking::RWLock;
use crate::mm::alloc::{allocate_pages, get_order};
use crate::types::PAGE_SIZE;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use crate::utils::zero_mem_region;
use core::arch::asm;

pub fn enable_irq() {
    unsafe { asm!("sti") };
}

pub fn disable_irq() {
    unsafe { asm!("cli") };
}

#[derive(Clone, Copy, Debug)]
pub enum IrqError {
    // Irq handler is already registered
    IrqHandlerExist,
    // vector is invalid
    VectorInvalid,
    // No free vector to use
    NoFreeVector,
}

type IrqHandlers = [RWLock<Option<fn(ctx: &X86ExceptionContext)>>; IDT_ENTRIES];
static IRQ_HANDLERS: ImmutAfterInitCell<IrqHandlers> = ImmutAfterInitCell::uninit();
static IRQ_HANDLERS_INITIALIZED: RWLock<bool> = RWLock::new(false);

fn try_init_irq_handlers() {
    if *IRQ_HANDLERS_INITIALIZED.lock_read() {
        // Already initialized
        return;
    }

    let mut init = IRQ_HANDLERS_INITIALIZED.lock_write();
    if *init {
        // Just initialized by someone else.
        return;
    }

    let order = get_order(core::mem::size_of::<IrqHandlers>());
    let vaddr = allocate_pages(order).expect("Failed to allocate IrqHandlers page");
    zero_mem_region(vaddr, vaddr + (1 << order) * PAGE_SIZE);
    IRQ_HANDLERS.reinit(unsafe { &*vaddr.as_ptr::<IrqHandlers>().cast::<IrqHandlers>() });
    *init = true;
}

pub fn register_interrupt_handler(
    vec: Option<u8>,
    func: fn(ctx: &X86ExceptionContext),
) -> Result<u8, IrqError> {
    // Make sure IRQ_HANDLERS has already been initialized
    try_init_irq_handlers();

    if let Some(vec) = vec {
        if vec as usize >= IDT_ENTRIES {
            return Err(IrqError::VectorInvalid);
        }

        let mut handler = (*IRQ_HANDLERS)[vec as usize].lock_write();
        if handler.is_some() {
            Err(IrqError::IrqHandlerExist)
        } else {
            *handler = Some(func);
            Ok(vec)
        }
    } else {
        for i in 32..IDT_ENTRIES {
            let mut handler = (*IRQ_HANDLERS)[i].lock_write();
            if handler.is_some() {
                continue;
            }
            *handler = Some(func);
            return Ok(i as u8);
        }
        Err(IrqError::NoFreeVector)
    }
}

// Generic interrupt handler
#[no_mangle]
extern "C" fn generic_interrupt_handler(ctx: &mut X86ExceptionContext) {
    (*LAPIC).eoi();

    let vec = ctx.vector;

    if vec < IDT_ENTRIES {
        if let Some(func) = *IRQ_HANDLERS[vec].lock_read() {
            func(ctx);
        }
    }
}
