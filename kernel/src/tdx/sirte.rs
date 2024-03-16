// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 Intel Corporation
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

use super::error::TdxError;
use super::tdp::{get_tdp_by_notify_vec, get_vcpu_cb, this_tdp};
use super::utils::{td_convert_kernel_pages, td_share_irte_hdr, TdpVmId};
use super::vcpu_comm::VcpuReqFlags;
use super::vlapic::vlapic_receive_intr;
use crate::address::VirtAddr;
use crate::cpu::idt::common::X86ExceptionContext;
use crate::cpu::lapic::LAPIC;
use crate::mm::{virt_to_phys, PAGE_SIZE};
use bitfield_struct::bitfield;
use core::sync::atomic::{fence, Ordering};

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
#[derive(Clone, Copy)]
union IrqEvent {
    msi: MsiEvent,
    irqchip: IrqChipEvent,
}

const IRQ_TYPE_IOAPIC: u32 = 1;
const IRQ_TYPE_MSI: u32 = 2;
#[repr(C)]
#[derive(Clone, Copy)]
struct SirtEntry {
    irq_type: u32,
    event: IrqEvent,
}

impl Default for SirtEntry {
    fn default() -> Self {
        SirtEntry {
            irq_type: 0,
            event: IrqEvent {
                msi: Default::default(),
            },
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
// Sirte page is 4K. Of the 4K, first 48 bytes are allocated for header
// which comprises of vec + rsvd(16 bytes) and shared buffer(32 bytes).
// The header is fixed at 48 bytes so that the remaining 4048 (4096- 48)
// bytes are exactly a multiple of sirte entry which is of 16 bytes in len.
// For this reason add padding to shared buffer to make it 32 bytes.
struct MetaData {
    // number of elements
    num_elem: u32,
    // sizeof of elements
    elem_size: u32,
    // offset from base, to read
    head: u32,
    // offset from base, to write
    tail: u32,
    // ele_num * ele_size
    size: u32,
    padding: [u32; 3],
}

impl MetaData {
    fn new(num_elem: usize, elem_size: usize) -> Self {
        Self {
            elem_size: elem_size as u32,
            num_elem: num_elem as u32,
            size: (elem_size * num_elem) as u32,
            ..Default::default()
        }
    }

    fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    fn update_head(&mut self) {
        let mut pos = self.head + 1;
        if pos >= self.num_elem {
            pos = 0;
        }
        self.head = pos;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SirteHeader {
    vec: u8,
    // padding to make buffer(PAGE_SIZE - Header) a multiple of struct SirtEntry (16 bytes)
    rsv: [u8; 15],
    mdata: MetaData,
}

#[repr(C)]
#[repr(align(4096))]
struct SirtePage {
    sirte_hdr: SirteHeader,
    data: [SirtEntry; 253],
}

impl SirtePage {
    fn new(notification_vector: u8) -> Self {
        let data_size = core::mem::size_of::<SirtePage>() - core::mem::size_of::<SirteHeader>();
        let elem_size = core::mem::size_of::<SirtEntry>();
        let num_elem = data_size / elem_size;
        Self {
            sirte_hdr: SirteHeader {
                vec: notification_vector,
                rsv: [0; 15],
                mdata: MetaData::new(num_elem, elem_size),
            },
            data: [SirtEntry::default(); 253],
        }
    }

    fn read(&mut self) -> Option<SirtEntry> {
        if !self.sirte_hdr.mdata.is_empty() {
            // Get the address of the SirtePage
            let entry = self.data[self.sirte_hdr.mdata.head as usize];
            // Ensure data is copied out before updating shared buffer head.
            fence(Ordering::SeqCst);
            self.sirte_hdr.mdata.update_head();
            Some(entry)
        } else {
            None
        }
    }
}

pub struct Sirte {
    vm_id: TdpVmId,
    page: SirtePage,
}

impl Sirte {
    pub fn init(&mut self, vm_id: TdpVmId) -> Result<(), TdxError> {
        self.vm_id = vm_id;
        let nv = this_tdp(self.vm_id)
            .get_sirte_vec()
            .ok_or(TdxError::Sirte)?;

        let vaddr = VirtAddr::from(core::ptr::addr_of!(self.page));
        let paddr = virt_to_phys(vaddr);
        td_convert_kernel_pages(paddr, paddr + PAGE_SIZE, true)?;

        self.page = SirtePage::new(nv);
        td_share_irte_hdr(paddr, vm_id)
    }

    pub fn handle_sirte(&mut self) {
        while let Some(sirte) = self.page.read() {
            match sirte.irq_type {
                IRQ_TYPE_MSI => unsafe {
                    vlapic_receive_intr(
                        self.vm_id,
                        sirte.event.msi.mode.trig_mode(),
                        sirte.event.msi.dest_id as u32,
                        !sirte.event.msi.mode.dest_mode(),
                        sirte.event.msi.mode.delivery_mode() as u32,
                        sirte.event.msi.vector,
                    );
                },
                IRQ_TYPE_IOAPIC => unsafe {
                    this_tdp(self.vm_id).get_vioapic().update_pinstate(
                        sirte.event.irqchip.pin as usize,
                        sirte.event.irqchip.level,
                        sirte.event.irqchip.source_id,
                    );
                },
                _ => {
                    log::error!("handle_sirte(): Incorrect irq_type = {}!", sirte.irq_type);
                    break;
                }
            }
        }
    }
}

pub fn handle_sirte_request(ctx: &X86ExceptionContext) {
    if let Some(tdp) = get_tdp_by_notify_vec(ctx.vector as u8) {
        if let Some(cb) = get_vcpu_cb(tdp.get_vm_id(), LAPIC.id()) {
            // Make a request to handle interrupt injection in vcpu
            // run loop instead of in interrupt context
            cb.make_request(VcpuReqFlags::SIRTE);
        }
    }
}
