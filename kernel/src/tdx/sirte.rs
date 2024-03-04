// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 Intel Corporation
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

use super::error::TdxError;
use super::tdp::this_tdp;
use super::utils::{td_convert_kernel_pages, td_share_irte_hdr, TdpVmId};
use crate::address::VirtAddr;
use crate::cpu::idt::common::X86ExceptionContext;
use crate::mm::{virt_to_phys, PAGE_SIZE};
use crate::utils::zero_mem_region;
use bitfield_struct::bitfield;

#[bitfield(u8)]
struct SirteMode {
    // physic: 0, logical: 1
    dest_mode: bool,
    // edge: 0, level: 1
    trig_mode: bool,
    #[bits(3)]
    delivery_mode: usize,
    #[bits(3)]
    rsv: usize,
}

// Each entry in the shared buffer is 16 bytes in len.
// This includes 4 bytes for type (msi/irqchip) and
// remaining 12 bytes for msi event or irqchip event.
// Add rsvd to ensure msi event is of 12 bytes in
// size.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MsiEvent {
    mode: SirteMode,
    vector: u8,
    dest_id: u8,
    rsvd: [u8; 9],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IrqChipEvent {
    pin: u32,
    level: u32,
    source_id: u32,
}

#[repr(C)]
union IrqEvent {
    msi: MsiEvent,
    irqchip: IrqChipEvent,
}

#[repr(C)]
struct SirtEntry {
    irq_type: u32,
    event: IrqEvent,
}

// The Sirte header is the meta data in the front of the SirtePage.
// It is constructed by vec + rsv and struct SharedBuf.
const SIRTE_HEADER_SIZE: usize = 48;

#[repr(C)]
#[derive(Debug, Default)]
// Sirte page is 4K. Of the 4K, first 48 bytes are allocated for header
// which comprises of vec + rsvd(16 bytes) and shared buffer(32 bytes).
// The header is fixed at 48 bytes so that the remaining 4048 (4096- 48)
// bytes are exactly a multiple of sirte entry which is of 16 bytes in len.
// For this reason add padding to shared buffer to make it 32 bytes.
struct SharedBuf {
    // number of elements
    ele_num: u32,
    // sizeof of elements
    ele_size: u32,
    // offset from base, to read
    head: u32,
    // offset from base, to write
    tail: u32,
    // ele_num * ele_size
    size: u32,
    padding: [u32; 3],
}

impl SharedBuf {
    fn new(buf_size: usize, ele_size: usize) -> Self {
        let ele_num = (buf_size - SIRTE_HEADER_SIZE) / ele_size;
        Self {
            ele_size: ele_size as u32,
            ele_num: ele_num as u32,
            size: (ele_size * ele_num) as u32,
            ..Default::default()
        }
    }
}

// Sirte page is 4K. Of the 4K, first 48 bytes are allocated for header
// which comprises of vec + rsvd(16 bytes) and shared buffer(32 bytes).
// The header is fixed at 48 bytes so that the remaining 4048 (4096- 48)
// data bytes are exactly a multiple of sirte entry which is of 16 bytes
// in len.
#[repr(C)]
#[repr(align(4096))]
struct SirtePage {
    vec: u8,
    // padding to make buffer(PAGE_SIZE - Header) a multiple of struct SirtEntry (16 bytes)
    rsv: [u8; 15],
    sbuf: SharedBuf,
}

pub struct Sirte {
    vm_id: TdpVmId,
    page: SirtePage,
}

impl Sirte {
    pub fn init(&mut self, vm_id: TdpVmId) -> Result<(), TdxError> {
        self.vm_id = vm_id;
        let vec = this_tdp(self.vm_id)
            .get_sirte_vec()
            .ok_or(TdxError::Sirte)?;
        let vaddr = VirtAddr::from(core::ptr::addr_of!(self.page));
        let paddr = virt_to_phys(vaddr);
        zero_mem_region(vaddr, vaddr + PAGE_SIZE);
        td_convert_kernel_pages(paddr, paddr + PAGE_SIZE, true)?;

        self.page.vec = vec;
        self.page.sbuf = SharedBuf::new(
            core::mem::size_of::<SirtePage>(),
            core::mem::size_of::<SirtEntry>(),
        );

        td_share_irte_hdr(paddr, vm_id)
    }
}

pub fn handle_sirte_request(_ctx: &X86ExceptionContext) {
    //TODO: handle sirte request and inject interrupts to TDP guest
}
