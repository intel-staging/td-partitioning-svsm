// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2024 Intel Corporation
//
// Author: Vijay Dhanraj <vijay.dhanraj@intel.com>

use super::error::TdxError;
use super::utils::TdpVmId;
use super::vlapic::vlapic_receive_intr;
use crate::cpu::idt::common::FIRST_DYNAMIC_VECTOR;
use crate::locking::SpinLock;
use crate::mm::pagetable::encrypt_mask;
use bitfield_struct::bitfield;

const VIOAPIC_BASE: u64 = 0xFEC00000;
const VIOAPIC_SIZE: u32 = 4096;

const IOAPIC_NUM_PINS: usize = 24;

const IOAPIC_VERSION: u32 = 0x11;

// Window register offset
const IOAPIC_REGSEL: u32 = 0x0;
const IOAPIC_WINDOW: u32 = 0x10;

const IOAPIC_ID_MASK: u32 = 0x0f000000;
const IOAPIC_ID_SHIFT: u32 = 24;

// Indexes into IO APIC
const IOAPIC_ID: u32 = 0x00;
const IOAPIC_VER: u32 = 0x01;
const IOAPIC_ARB: u32 = 0x02;
const IOAPIC_REDTBL: u32 = 0x10;

// Fields in redirection table entry
const MAX_RTE_SHIFT: u32 = 16;

const IOAPIC_RTE_MASK_INTERRRUPT: u64 = 0x0000000000010000;

const IOAPIC_RTE_MASK_CLR: bool = false; // Interrupt Mask: Clear ==> 0
const IOAPIC_RTE_MASK_SET: bool = true; // Interrupt Mask: Set ==> 1

const IOAPIC_RTE_TRGRMODE_EDGE: bool = false; // Trigger Mode: Edge ==> 0
const IOAPIC_RTE_TRGRMODE_LEVEL: bool = true; // Trigger Mode: Level ==> 1

const IOAPIC_RTE_DESTMODE_PHY: bool = false; // Destination Mode: Physical => 0

const IOAPIC_RTE_REM_IRR_CLR: bool = false; // Remote IRR: Read-Only ==> 0
const IOAPIC_RTE_REM_IRR_SET: bool = true; // Remote IRR: Read-Only ==> 1

const IOAPIC_RTE_RO_BITS: u32 = 0x00004000 | 0x00001000; //Remote IRR and Delivery Status bits

#[bitfield(u64)]
struct Rte {
    vector: u8,
    #[bits(3)]
    delivery_mode: u8,
    // physic: 0, logical: 1
    dest_mode: bool,
    delivery_status: bool,
    polarity: bool,
    remote_irr: bool,
    // edge: 0, level: 1
    trig_mode: bool,
    intr_mask: bool,
    #[bits(7)]
    rsv: u8,
    rsvd1: u32,
    dest_field: u8,
}

#[derive(Debug)]
struct RawVioapic {
    vm_id: TdpVmId,
    init_done: bool,
    id: u32,
    ioregsel: u32,
    irr: u32,
    pin_state: [u32; IOAPIC_NUM_PINS],
    base_addr: u64,
    rte: [Rte; IOAPIC_NUM_PINS],
}

impl RawVioapic {
    fn generate_intr(&mut self, pin: usize) {
        let rte: Rte = self.rte[pin];

        if rte.intr_mask() == IOAPIC_RTE_MASK_SET {
            log::error!("ioapic pin {} masked", pin);
        } else {
            let phys = rte.dest_mode() == IOAPIC_RTE_DESTMODE_PHY;
            let delmode = rte.delivery_mode();
            let level = rte.trig_mode() == IOAPIC_RTE_TRGRMODE_LEVEL;

            // For level trigger irq, avoid send intr if
            // previous one hasn't received EOI
            if !level || !rte.remote_irr() {
                if level {
                    self.rte[pin].set_remote_irr(IOAPIC_RTE_REM_IRR_SET);
                }
                vlapic_receive_intr(
                    self.vm_id,
                    level,
                    rte.dest_field() as u32,
                    phys,
                    delmode as u32,
                    rte.vector(),
                );
            }
        }
    }

    fn need_intr(&self, pin: usize) -> bool {
        if pin < IOAPIC_NUM_PINS {
            (self.irr & (1 << pin)) != 0
        } else {
            false
        }
    }

    fn indirect_write(&mut self, data: u32) {
        let regnum = self.ioregsel & 0xff;
        let pincount = IOAPIC_NUM_PINS as u32;

        match regnum {
            IOAPIC_ID => self.id = (data & IOAPIC_ID_MASK) >> IOAPIC_ID_SHIFT,
            IOAPIC_VER => {} // read only
            IOAPIC_ARB => {} // read only
            _ => {
                // In this switch statement, regnum shall either be IOAPIC_ID or
                // IOAPIC_VER or IOAPIC_ARB.
                // All the other cases will be handled properly later after this
                // switch statement.
            }
        }

        if (regnum >= IOAPIC_REDTBL) && (regnum < (IOAPIC_REDTBL + pincount * 2)) {
            let addr_offset = regnum - IOAPIC_REDTBL;
            let pin: usize = (addr_offset >> 1) as usize;

            let last: Rte = self.rte[pin];
            let mut new_data: u64 = last.0;

            if (addr_offset & 1) != 0 {
                // clear upper 32bits
                new_data &= 0xffffffffu64;
                new_data |= (data as u64) << 32;
            } else {
                new_data &= (0xffffffffu64 << 32) | (IOAPIC_RTE_RO_BITS as u64);
                new_data |= (data & !IOAPIC_RTE_RO_BITS) as u64;
            }

            let mut new = Rte::from_bits(new_data);

            // In some special scenarios, the LAPIC somehow hasn't send
            // EOI to IOAPIC which cause the Remote IRR bit can't be clear.
            // To clear it, some OSes will use EOI Register to clear it for
            // 0x20 version IOAPIC, otherwise use switch Trigger Mode to
            // Edge Sensitive to clear it.
            if new.trig_mode() == IOAPIC_RTE_TRGRMODE_EDGE {
                new.set_remote_irr(IOAPIC_RTE_REM_IRR_CLR);
            }

            self.rte[pin] = new;

            // Generate an interrupt if the following conditions are met:
            // - pin is not masked
            // - level triggered interrupt and previous interrupt has been EOIed
            // - pin level is asserted
            if (self.rte[pin].intr_mask() == IOAPIC_RTE_MASK_CLR
                && self.rte[pin].trig_mode() == IOAPIC_RTE_TRGRMODE_LEVEL
                && self.rte[pin].remote_irr() == IOAPIC_RTE_REM_IRR_CLR)
                && self.need_intr(pin)
            {
                self.generate_intr(pin);
            }
        }
    }

    fn indirect_read(&self) -> u32 {
        let regnum = self.ioregsel & 0xff;
        let pincount = IOAPIC_NUM_PINS as u32;
        let mut val = 0;

        match regnum {
            IOAPIC_ID => {
                val = self.id << IOAPIC_ID_SHIFT;
            }
            IOAPIC_VER => {
                val = ((pincount - 1) << MAX_RTE_SHIFT) | IOAPIC_VERSION;
            }
            IOAPIC_ARB => {
                val = self.id << IOAPIC_ID_SHIFT;
            }
            _ => {
                // In this switch statement, regnum shall either be IOAPIC_ID or
                // IOAPIC_VER or IOAPIC_ARB.
                // All the other cases will be handled properly later after this
                // switch statement.
            }
        }

        if (regnum >= IOAPIC_REDTBL) && (regnum < (IOAPIC_REDTBL + (pincount * 2))) {
            let addr_offset = regnum - IOAPIC_REDTBL;
            let pin: usize = (addr_offset >> 1) as usize;
            if (addr_offset & 0x1) != 0 {
                val = (self.rte[pin].0 >> 32) as u32;
            } else {
                val = self.rte[pin].0 as u32;
            }
        }
        val
    }

    fn mmio_read(&mut self, gpa: u64, size: u32) -> Result<u32, TdxError> {
        if size != 4 {
            log::error!("All reads to IOAPIC must be 32-bits in size");
            return Err(TdxError::Vioapic);
        }

        let offset: u32 = (gpa - self.base_addr) as u32;
        match offset {
            IOAPIC_REGSEL => Ok(self.ioregsel),
            IOAPIC_WINDOW => Ok(self.indirect_read()),
            _ => Ok(0xffffffffu32),
        }
    }

    fn mmio_write(&mut self, gpa: u64, data: u32, size: u32) -> Result<(), TdxError> {
        if size != 4 {
            log::error!("All reads to IOAPIC must be 32-bits in size");
            return Err(TdxError::Vioapic);
        }

        let offset: u32 = (gpa - self.base_addr) as u32;
        match offset {
            IOAPIC_REGSEL => self.ioregsel = data & 0xff,
            IOAPIC_WINDOW => self.indirect_write(data),
            _ => {
                log::error!("Unknown vioapic write offset {}", offset);
                return Err(TdxError::Vioapic);
            }
        }
        Ok(())
    }

    fn get_pin_state(&mut self, pin: usize, level: u32, source_id: u32) -> bool {
        if level != 0 {
            self.pin_state[pin] |= 1 << source_id;
        } else {
            self.pin_state[pin] &= !(1 << source_id);
        }

        self.pin_state[pin] != 0
    }

    fn update_pinstate(&mut self, pin: usize, level: u32, source_id: u32) {
        let pin_mask: u32 = 1 << pin;
        let rte: Rte = self.rte[pin];

        if rte.intr_mask() == IOAPIC_RTE_MASK_SET {
            return;
        }

        let asserted = self.get_pin_state(pin, level, source_id);
        if !asserted {
            self.irr &= !pin_mask;
            return;
        }

        // coalesced interrupt
        let old_irr = self.irr;
        self.irr |= pin_mask;
        if (rte.trig_mode() == IOAPIC_RTE_TRGRMODE_EDGE) && (old_irr == self.irr) {
            return;
        }

        self.generate_intr(pin);
    }

    fn broadcast_eoi(&mut self, vector: u8) -> Result<(), TdxError> {
        if vector < FIRST_DYNAMIC_VECTOR {
            log::error!("Invalid vector {}", vector);
            return Err(TdxError::Vioapic);
        }

        for i in 0..IOAPIC_NUM_PINS {
            let rte: Rte = self.rte[i];
            if rte.vector() != vector || rte.remote_irr() == IOAPIC_RTE_REM_IRR_CLR {
                continue;
            }

            self.rte[i].set_remote_irr(IOAPIC_RTE_REM_IRR_CLR);

            if self.need_intr(i) {
                self.generate_intr(i);
            }
        }
        Ok(())
    }

    fn get_mmio_range(&self) -> (u64, u64) {
        if !self.init_done {
            return (u64::MAX, 0);
        }

        // TODO: Current TDX guest seems to be enlightened but need
        // to consider for unenlightened guest as well.
        let base = self.base_addr;
        (
            base | (encrypt_mask() as u64),
            (base + (VIOAPIC_SIZE as u64)) | (encrypt_mask() as u64),
        )
    }

    fn init(&mut self) {
        self.base_addr = VIOAPIC_BASE;

        // Clear pin states and mask all interrupts
        for i in 0..IOAPIC_NUM_PINS {
            self.pin_state[i] = 0;
            self.rte[i] = Rte::from_bits(IOAPIC_RTE_MASK_INTERRRUPT);
        }

        self.init_done = true;
    }

    fn new(vm_id: TdpVmId) -> Self {
        RawVioapic {
            vm_id,
            init_done: false,
            id: 0,
            ioregsel: 0,
            irr: 0,
            base_addr: 0,
            pin_state: [0; IOAPIC_NUM_PINS],
            rte: [Rte::from_bits(0); IOAPIC_NUM_PINS],
        }
    }
}

#[derive(Debug)]
pub struct Vioapic {
    raw: SpinLock<RawVioapic>,
}

impl Vioapic {
    pub fn new(vm_id: TdpVmId) -> Self {
        Vioapic {
            raw: SpinLock::new(RawVioapic::new(vm_id)),
        }
    }

    pub fn init(&self) {
        self.raw.lock().init();
    }

    pub fn get_mmio_range(&self) -> (u64, u64) {
        self.raw.lock().get_mmio_range()
    }

    pub fn broadcast_eoi(&self, vector: u8) -> Result<(), TdxError> {
        self.raw.lock().broadcast_eoi(vector)
    }

    pub fn mmio_read(&self, gpa: u64, size: u32) -> Result<u32, TdxError> {
        self.raw.lock().mmio_read(gpa, size)
    }

    pub fn mmio_write(&self, gpa: u64, data: u32, size: u32) -> Result<(), TdxError> {
        self.raw.lock().mmio_write(gpa, data, size)
    }

    pub fn update_pinstate(&self, pin: usize, level: u32, source_id: u32) {
        assert!(pin < IOAPIC_NUM_PINS);
        self.raw.lock().update_pinstate(pin, level, source_id)
    }
}
