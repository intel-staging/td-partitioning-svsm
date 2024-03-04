// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

use super::error::{ErrExcp, TdxError};
use super::percpu::{this_vcpu, this_vcpu_mut};
use super::tdcall::tdvmcall_wrmsr;
use super::utils::TdpVmId;
use super::vcpu::ResetMode;
use super::vcpu_comm::VcpuReqFlags;
use super::vmcs_lib::VmcsField64Control;
use crate::address::{PhysAddr, VirtAddr};
use crate::cpu::msr::MSR_IA32_TSC_DEADLINE;
use crate::mm::alloc::allocate_zeroed_page;
use crate::mm::virt_to_phys;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// APIC Registers
const APIC_OFFSET_ID: u32 = 0x20; // Local APIC ID
const APIC_OFFSET_VER: u32 = 0x30; // Local APIC Version
const APIC_OFFSET_TPR: u32 = 0x80; // Task Priority Register
const APIC_OFFSET_PPR: u32 = 0xA0; // Processor Priority Register
const APIC_OFFSET_LDR: u32 = 0xD0; // Logical Destination
const APIC_OFFSET_DFR: u32 = 0xE0; // Destination Format Register
const APIC_OFFSET_SVR: u32 = 0xF0; // Spurious Vector Registe
const APIC_OFFSET_ISR0: u32 = 0x100; // In Service Register
const APIC_OFFSET_ISR1: u32 = 0x110;
const APIC_OFFSET_ISR2: u32 = 0x120;
const APIC_OFFSET_ISR3: u32 = 0x130;
const APIC_OFFSET_ISR4: u32 = 0x140;
const APIC_OFFSET_ISR5: u32 = 0x150;
const APIC_OFFSET_ISR6: u32 = 0x160;
const APIC_OFFSET_ISR7: u32 = 0x170;
const APIC_OFFSET_TMR0: u32 = 0x180; // Trigger Mode Register
const APIC_OFFSET_TMR1: u32 = 0x190;
const APIC_OFFSET_TMR2: u32 = 0x1A0;
const APIC_OFFSET_TMR3: u32 = 0x1B0;
const APIC_OFFSET_TMR4: u32 = 0x1C0;
const APIC_OFFSET_TMR5: u32 = 0x1D0;
const APIC_OFFSET_TMR6: u32 = 0x1E0;
const APIC_OFFSET_TMR7: u32 = 0x1F0;
const APIC_OFFSET_IRR0: u32 = 0x200; // Interrupt Request Register
const APIC_OFFSET_IRR1: u32 = 0x210;
const APIC_OFFSET_IRR2: u32 = 0x220;
const APIC_OFFSET_IRR3: u32 = 0x230;
const APIC_OFFSET_IRR4: u32 = 0x240;
const APIC_OFFSET_IRR5: u32 = 0x250;
const APIC_OFFSET_IRR6: u32 = 0x260;
const APIC_OFFSET_IRR7: u32 = 0x270;
const APIC_OFFSET_ESR: u32 = 0x280; // Error Status Register
const APIC_OFFSET_CMCI_LVT: u32 = 0x2F0; // Local Vector Table (CMCI)
const APIC_OFFSET_ICR_LOW: u32 = 0x300; // Interrupt Command Register
const APIC_OFFSET_ICR_HI: u32 = 0x310;
const APIC_OFFSET_TIMER_LVT: u32 = 0x320; // Local Vector Table (Timer)
const APIC_OFFSET_THERM_LVT: u32 = 0x330; // Local Vector Table (Thermal)
const APIC_OFFSET_PERF_LVT: u32 = 0x340; // Local Vector Table (PMC)
const APIC_OFFSET_LINT0_LVT: u32 = 0x350; // Local Vector Table (LINT0)
const APIC_OFFSET_LINT1_LVT: u32 = 0x360; // Local Vector Table (LINT1)
const APIC_OFFSET_ERROR_LVT: u32 = 0x370; // Local Vector Table (ERROR)
const APIC_OFFSET_TIMER_ICR: u32 = 0x380; // Timer's Initial Count
const APIC_OFFSET_TIMER_DCR: u32 = 0x3E0; // Timer's Divide Configuration
const APIC_OFFSET_SELF_IPI: u32 = 0x3F0; // Self IPI Register

// constants relating to APIC ID registers
const APIC_ID_SHIFT: u32 = 24;

// fields in VER
const MAXLVTSHIFT: u32 = 16;

// fields in SVR
const APIC_SVR_VECTOR: u32 = 0x000000ff;
const APIC_SVR_ENABLE: u32 = 0x00000100;

// fields in LVT1/2
const APIC_LVT_VECTOR: u32 = 0x000000ff;
const APIC_LVT_DM: u32 = 0x00000700;
const APIC_LVT_DS: u32 = 0x00001000;
const APIC_LVT_IIPP: u32 = 0x00002000;
const APIC_LVT_RIRR: u32 = 0x00004000;
const APIC_LVT_TM: u32 = 0x00008000;
const APIC_LVT_M: u32 = 0x00010000;

// fields in LVT Timer
const APIC_LVTT_TM: u32 = 0x00060000;

// LVT table indices
const APIC_LVT_TIMER: usize = 0;
const APIC_LVT_THERMAL: usize = 1;
const APIC_LVT_PMC: usize = 2;
const APIC_LVT_LINT0: usize = 3;
const APIC_LVT_LINT1: usize = 4;
const APIC_LVT_ERROR: usize = 5;

const DEFAULT_APIC_BASE: u64 = 0xFEE0_0000;
const VLAPIC_VERSION: u32 = 16;
const VLAPIC_MAXLVT_INDEX: u32 = 6; // we have 7 lvt

const APICBASE_BSP: u64 = 0x00000100;
const APICBASE_X2APIC: u64 = 0x00000400;
const APICBASE_XAPIC: u64 = 0x00000800;
const APICBASE_LAPIC_MODE: u64 = APICBASE_XAPIC | APICBASE_X2APIC;
const APICBASE_ENABLED: u64 = 0x00000800;
const APICBASE_RESERVED: u64 = 0xFFFFFFF0_000002FF;

const LOGICAL_ID_MASK: u32 = 0xF;
const CLUSTER_ID_MASK: u32 = 0xFFFF0;

#[repr(C)]
#[derive(Debug)]
struct LapicReg {
    v: u32,
    pad: [u32; 3],
}

#[repr(C)]
#[derive(Debug)]
struct LapicPage {
    rsv0: [LapicReg; 2],
    id: LapicReg,      //020
    version: LapicReg, //030
    rsv1: [LapicReg; 4],
    tpr: LapicReg,      //080
    apr: LapicReg,      //090
    ppr: LapicReg,      //0A0
    eoi: LapicReg,      //0B0
    rrd: LapicReg,      //0C0
    ldr: LapicReg,      //0D0
    dfr: LapicReg,      //0E0
    svr: LapicReg,      //0F0
    isr: [LapicReg; 8], //100 -- 170
    tmr: [LapicReg; 8], //180 -- 1F0
    irr: [LapicReg; 8], //200 -- 270
    esr: LapicReg,      //280
    rsv2: [LapicReg; 6],
    lvt_cmci: LapicReg,  //2F0
    icr_lo: LapicReg,    //300
    icr_hi: LapicReg,    //310
    lvt: [LapicReg; 6],  //320 -- 370
    icr_timer: LapicReg, //380
    ccr_timer: LapicReg, //390
    rsv3: [LapicReg; 4],
    dcr_timer: LapicReg, //3E0
    self_ipi: LapicReg,  //3F0
    //roundup sizeof current struct to 4KB
    rsv4: [LapicReg; 192], //400 -- FF0
}

#[derive(Debug)]
struct VlapicRegs {
    apic_page: VirtAddr,
    apic_base: u64,
}

impl VlapicRegs {
    fn new(apic_base: u64) -> Self {
        Self {
            apic_page: allocate_zeroed_page().expect("Failed to allocate vlapic register page"),
            apic_base,
        }
    }

    fn reg_page(&self) -> &LapicPage {
        unsafe { &*self.apic_page.as_ptr::<LapicPage>().cast::<LapicPage>() }
    }

    fn reg_page_mut(&mut self) -> &mut LapicPage {
        unsafe { &mut *self.apic_page.as_mut_ptr::<LapicPage>().cast::<LapicPage>() }
    }

    fn get_reg(&self, offset: u32) -> u32 {
        let apic_page = self.reg_page();
        match offset {
            APIC_OFFSET_ID => apic_page.id.v,
            APIC_OFFSET_VER => apic_page.version.v,
            APIC_OFFSET_TPR => apic_page.tpr.v,
            APIC_OFFSET_PPR => apic_page.ppr.v,
            APIC_OFFSET_LDR => apic_page.ldr.v,
            APIC_OFFSET_DFR => apic_page.dfr.v,
            APIC_OFFSET_SVR => apic_page.svr.v,
            APIC_OFFSET_ISR0 => apic_page.isr[0].v,
            APIC_OFFSET_ISR1 => apic_page.isr[1].v,
            APIC_OFFSET_ISR2 => apic_page.isr[2].v,
            APIC_OFFSET_ISR3 => apic_page.isr[3].v,
            APIC_OFFSET_ISR4 => apic_page.isr[4].v,
            APIC_OFFSET_ISR5 => apic_page.isr[5].v,
            APIC_OFFSET_ISR6 => apic_page.isr[6].v,
            APIC_OFFSET_ISR7 => apic_page.isr[7].v,
            APIC_OFFSET_TMR0 => apic_page.tmr[0].v,
            APIC_OFFSET_TMR1 => apic_page.tmr[1].v,
            APIC_OFFSET_TMR2 => apic_page.tmr[2].v,
            APIC_OFFSET_TMR3 => apic_page.tmr[3].v,
            APIC_OFFSET_TMR4 => apic_page.tmr[4].v,
            APIC_OFFSET_TMR5 => apic_page.tmr[5].v,
            APIC_OFFSET_TMR6 => apic_page.tmr[6].v,
            APIC_OFFSET_TMR7 => apic_page.tmr[7].v,
            APIC_OFFSET_IRR0 => apic_page.irr[0].v,
            APIC_OFFSET_IRR1 => apic_page.irr[1].v,
            APIC_OFFSET_IRR2 => apic_page.irr[2].v,
            APIC_OFFSET_IRR3 => apic_page.irr[3].v,
            APIC_OFFSET_IRR4 => apic_page.irr[4].v,
            APIC_OFFSET_IRR5 => apic_page.irr[5].v,
            APIC_OFFSET_IRR6 => apic_page.irr[6].v,
            APIC_OFFSET_IRR7 => apic_page.irr[7].v,
            APIC_OFFSET_ESR => apic_page.esr.v,
            APIC_OFFSET_ICR_LOW => apic_page.icr_lo.v,
            APIC_OFFSET_ICR_HI => apic_page.icr_hi.v,
            APIC_OFFSET_CMCI_LVT => apic_page.lvt_cmci.v,
            APIC_OFFSET_TIMER_LVT => apic_page.lvt[APIC_LVT_TIMER].v,
            APIC_OFFSET_THERM_LVT => apic_page.lvt[APIC_LVT_THERMAL].v,
            APIC_OFFSET_PERF_LVT => apic_page.lvt[APIC_LVT_PMC].v,
            APIC_OFFSET_LINT0_LVT => apic_page.lvt[APIC_LVT_LINT0].v,
            APIC_OFFSET_LINT1_LVT => apic_page.lvt[APIC_LVT_LINT1].v,
            APIC_OFFSET_ERROR_LVT => apic_page.lvt[APIC_LVT_ERROR].v,
            APIC_OFFSET_TIMER_ICR => apic_page.icr_timer.v,
            APIC_OFFSET_TIMER_DCR => apic_page.dcr_timer.v,
            _ => panic!("get_reg: not support lapic reg offset {:#018x}", offset),
        }
    }

    fn set_reg(&mut self, offset: u32, val: u32) {
        let apic_page = self.reg_page_mut();
        match offset {
            APIC_OFFSET_ID => apic_page.id.v = val,
            APIC_OFFSET_VER => apic_page.version.v = val,
            APIC_OFFSET_TPR => apic_page.tpr.v = val,
            APIC_OFFSET_PPR => apic_page.ppr.v = val,
            APIC_OFFSET_LDR => apic_page.ldr.v = val,
            APIC_OFFSET_DFR => apic_page.dfr.v = val,
            APIC_OFFSET_SVR => apic_page.svr.v = val,
            APIC_OFFSET_ISR0 => apic_page.isr[0].v = val,
            APIC_OFFSET_ISR1 => apic_page.isr[1].v = val,
            APIC_OFFSET_ISR2 => apic_page.isr[2].v = val,
            APIC_OFFSET_ISR3 => apic_page.isr[3].v = val,
            APIC_OFFSET_ISR4 => apic_page.isr[4].v = val,
            APIC_OFFSET_ISR5 => apic_page.isr[5].v = val,
            APIC_OFFSET_ISR6 => apic_page.isr[6].v = val,
            APIC_OFFSET_ISR7 => apic_page.isr[7].v = val,
            APIC_OFFSET_TMR0 => apic_page.tmr[0].v = val,
            APIC_OFFSET_TMR1 => apic_page.tmr[1].v = val,
            APIC_OFFSET_TMR2 => apic_page.tmr[2].v = val,
            APIC_OFFSET_TMR3 => apic_page.tmr[3].v = val,
            APIC_OFFSET_TMR4 => apic_page.tmr[4].v = val,
            APIC_OFFSET_TMR5 => apic_page.tmr[5].v = val,
            APIC_OFFSET_TMR6 => apic_page.tmr[6].v = val,
            APIC_OFFSET_TMR7 => apic_page.tmr[7].v = val,
            APIC_OFFSET_IRR0 => apic_page.irr[0].v = val,
            APIC_OFFSET_IRR1 => apic_page.irr[1].v = val,
            APIC_OFFSET_IRR2 => apic_page.irr[2].v = val,
            APIC_OFFSET_IRR3 => apic_page.irr[3].v = val,
            APIC_OFFSET_IRR4 => apic_page.irr[4].v = val,
            APIC_OFFSET_IRR5 => apic_page.irr[5].v = val,
            APIC_OFFSET_IRR6 => apic_page.irr[6].v = val,
            APIC_OFFSET_IRR7 => apic_page.irr[7].v = val,
            APIC_OFFSET_ESR => apic_page.esr.v = val,
            APIC_OFFSET_ICR_LOW => apic_page.icr_lo.v = val,
            APIC_OFFSET_ICR_HI => apic_page.icr_hi.v = val,
            APIC_OFFSET_CMCI_LVT => apic_page.lvt_cmci.v = val,
            APIC_OFFSET_TIMER_LVT => apic_page.lvt[APIC_LVT_TIMER].v = val,
            APIC_OFFSET_THERM_LVT => apic_page.lvt[APIC_LVT_THERMAL].v = val,
            APIC_OFFSET_PERF_LVT => apic_page.lvt[APIC_LVT_PMC].v = val,
            APIC_OFFSET_LINT0_LVT => apic_page.lvt[APIC_LVT_LINT0].v = val,
            APIC_OFFSET_LINT1_LVT => apic_page.lvt[APIC_LVT_LINT1].v = val,
            APIC_OFFSET_ERROR_LVT => apic_page.lvt[APIC_LVT_ERROR].v = val,
            APIC_OFFSET_TIMER_ICR => apic_page.icr_timer.v = val,
            APIC_OFFSET_TIMER_DCR => apic_page.dcr_timer.v = val,
            APIC_OFFSET_SELF_IPI => apic_page.self_ipi.v = val,
            _ => panic!("set_reg: not support lapic reg offset {:#018x}", offset),
        }
    }

    fn is_x2apic(&self) -> bool {
        self.apic_base & APICBASE_LAPIC_MODE == (APICBASE_XAPIC | APICBASE_X2APIC)
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct VlapicTimer {
    mode: u32,
    tmicr: u32,
    divisor_shift: u32,
    timeout: u64,
    period_in_cycle: u64,
}

fn stop_tsc_deadline_timer() {
    tdvmcall_wrmsr(MSR_IA32_TSC_DEADLINE, 0).unwrap();
}

pub struct Vlapic {
    vm_id: TdpVmId,
    apic_id: u32,
    is_bsp: bool,
    regs: VlapicRegs,
    vtimer: VlapicTimer,

    esr_pending: u32,
    esr_firing: AtomicBool,

    // used for xapic mode for IRR/ISR/PPR emulation
    in_service_vec: u8,

    // Posted Interrupt Requested, used for x2apic mode w/ VID(virtual interrupt delivery)
    pir: [AtomicU64; 4],

    // 256 eoi exit bit
    eoi_exit_bitmap: [AtomicU64; 4],
}

impl Vlapic {
    pub fn init(&mut self, vm_id: TdpVmId, apic_id: u32, is_bsp: bool) {
        self.vm_id = vm_id;
        self.apic_id = apic_id;
        self.is_bsp = is_bsp;
        self.regs = VlapicRegs::new(DEFAULT_APIC_BASE);
        self.vtimer = VlapicTimer {
            mode: 0,
            tmicr: 0,
            divisor_shift: 0,
            timeout: 0,
            period_in_cycle: 0,
        };
        self.esr_pending = 0;
        self.esr_firing = AtomicBool::new(false);
        self.in_service_vec = 0;
        self.pir = [
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
        ];
        self.eoi_exit_bitmap = [
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
        ];

        self.reset(ResetMode::PowerOnReset);
    }

    pub fn reset(&mut self, mode: ResetMode) {
        let preserved_lapic_mode = self.get_apicbase() & APICBASE_LAPIC_MODE;
        let preserved_apic_id = self.get_reg(APIC_OFFSET_ID);
        self.regs.apic_base = DEFAULT_APIC_BASE;
        if self.is_bsp {
            self.regs.apic_base |= APICBASE_BSP;
        }
        if mode == ResetMode::InitReset {
            if (preserved_lapic_mode & APICBASE_ENABLED) != 0 {
                // Per SDM 10.12.5.1 vol.3, need to preserve lapic mode after INIT
                self.regs.apic_base |= preserved_lapic_mode;
            }
        } else {
            // Upon reset, vlapic is set to xAPIC mode.
            self.regs.apic_base |= APICBASE_XAPIC;
        }

        if mode == ResetMode::InitReset {
            if (preserved_lapic_mode & APICBASE_ENABLED) != 0 {
                // the local APIC ID register should be preserved in XAPIC or X2APIC mode
                self.set_reg(APIC_OFFSET_ID, preserved_apic_id);
            }
        } else {
            let mut id = self.apic_id;
            if !self.is_x2apic() {
                id <<= APIC_ID_SHIFT;
            }
            self.set_reg(APIC_OFFSET_ID, id);
        }
        self.set_reg(
            APIC_OFFSET_VER,
            VLAPIC_VERSION | (VLAPIC_MAXLVT_INDEX << MAXLVTSHIFT),
        );
        self.set_reg(APIC_OFFSET_DFR, 0xffffffff);
        self.set_reg(APIC_OFFSET_SVR, APIC_SVR_VECTOR);
        self.mask_lvts();
        self.set_reg(APIC_OFFSET_TIMER_ICR, 0);
        self.write_dcr(0);
        stop_tsc_deadline_timer();
        self.update_timer(0, 0);
        self.reset_tmr();
    }

    pub fn get_apic_page_addr(&self) -> PhysAddr {
        virt_to_phys(self.regs.apic_page)
    }

    fn reset_tmr(&mut self) {
        let mut i = 0;
        while i < 8 {
            self.set_reg(APIC_OFFSET_TMR0 + i * 16, 0);
            i += 1;
        }

        if self.is_x2apic() {
            self.eoi_exit_bitmap[0].store(0, Ordering::Release);
            self.eoi_exit_bitmap[1].store(0, Ordering::Release);
            self.eoi_exit_bitmap[2].store(0, Ordering::Release);
            self.eoi_exit_bitmap[3].store(0, Ordering::Release);
            self.set_vmcs_eoi_exit_bitmap();
        }
    }

    fn set_vmcs_eoi_exit_bitmap(&self) {
        if self.is_x2apic() {
            let vmcs = this_vcpu(self.vm_id).get_vmcs();

            vmcs.write64(
                VmcsField64Control::EOI_EXIT_BITMAP0,
                self.eoi_exit_bitmap[0].load(Ordering::Acquire),
            );
            vmcs.write64(
                VmcsField64Control::EOI_EXIT_BITMAP1,
                self.eoi_exit_bitmap[1].load(Ordering::Acquire),
            );
            vmcs.write64(
                VmcsField64Control::EOI_EXIT_BITMAP2,
                self.eoi_exit_bitmap[2].load(Ordering::Acquire),
            );
            vmcs.write64(
                VmcsField64Control::EOI_EXIT_BITMAP3,
                self.eoi_exit_bitmap[3].load(Ordering::Acquire),
            );
        }
    }

    fn write_lvt(&mut self, offset: u32, data: u32) {
        let mask = match offset {
            APIC_OFFSET_CMCI_LVT | APIC_OFFSET_THERM_LVT | APIC_OFFSET_PERF_LVT => {
                APIC_LVT_M | APIC_LVT_DS | APIC_LVT_VECTOR | APIC_LVT_DM
            }
            APIC_OFFSET_TIMER_LVT => APIC_LVT_M | APIC_LVT_DS | APIC_LVT_VECTOR | APIC_LVTT_TM,
            APIC_OFFSET_LINT0_LVT | APIC_OFFSET_LINT1_LVT => {
                APIC_LVT_M
                    | APIC_LVT_DS
                    | APIC_LVT_VECTOR
                    | APIC_LVT_TM
                    | APIC_LVT_RIRR
                    | APIC_LVT_IIPP
            }
            APIC_OFFSET_ERROR_LVT => APIC_LVT_M | APIC_LVT_DS | APIC_LVT_VECTOR,
            _ => {
                panic!(
                    "write_lvt: not support lapic lvt reg offset {:#018x}",
                    offset
                );
            }
        };
        let val = if (self.get_reg(APIC_OFFSET_SVR) & APIC_SVR_ENABLE) == 0 {
            (data | APIC_LVT_M) & mask
        } else {
            data & mask
        };

        if offset == APIC_OFFSET_TIMER_LVT {
            // update lvtt
            let timer_mode = val & APIC_LVTT_TM;
            if self.vtimer.mode != timer_mode {
                stop_tsc_deadline_timer();
                self.update_timer(0, 0);
                self.vtimer.mode = timer_mode;
            }
        }
        self.set_reg(offset, val);
    }

    fn write_dcr(&mut self, new: u32) {
        self.set_reg(APIC_OFFSET_TIMER_DCR, new);
        self.vtimer.divisor_shift = (((new & 0x3) | ((new & 0x8) >> 1)) + 1) & 0x7;
    }

    fn update_timer(&mut self, timeout: u64, period: u64) {
        self.vtimer.timeout = timeout;
        self.vtimer.period_in_cycle = period;
    }

    fn mask_lvts(&mut self) {
        self.write_lvt(
            APIC_OFFSET_CMCI_LVT,
            self.get_reg(APIC_OFFSET_CMCI_LVT) | APIC_LVT_M,
        );
        self.write_lvt(
            APIC_OFFSET_TIMER_LVT,
            self.get_reg(APIC_OFFSET_TIMER_LVT) | APIC_LVT_M,
        );
        self.write_lvt(
            APIC_OFFSET_THERM_LVT,
            self.get_reg(APIC_OFFSET_THERM_LVT) | APIC_LVT_M,
        );
        self.write_lvt(
            APIC_OFFSET_PERF_LVT,
            self.get_reg(APIC_OFFSET_PERF_LVT) | APIC_LVT_M,
        );
        self.write_lvt(
            APIC_OFFSET_LINT0_LVT,
            self.get_reg(APIC_OFFSET_LINT0_LVT) | APIC_LVT_M,
        );
        self.write_lvt(
            APIC_OFFSET_LINT1_LVT,
            self.get_reg(APIC_OFFSET_LINT1_LVT) | APIC_LVT_M,
        );
        self.write_lvt(
            APIC_OFFSET_ERROR_LVT,
            self.get_reg(APIC_OFFSET_ERROR_LVT) | APIC_LVT_M,
        );
    }

    #[inline(always)]
    fn get_reg(&self, offset: u32) -> u32 {
        self.regs.get_reg(offset)
    }

    #[inline(always)]
    fn set_reg(&mut self, offset: u32, val: u32) {
        self.regs.set_reg(offset, val);
    }

    #[inline(always)]
    fn is_x2apic(&self) -> bool {
        self.regs.is_x2apic()
    }

    fn build_x2apic_id(&mut self) {
        let logical_id = self.apic_id & LOGICAL_ID_MASK;
        let cluster_id = (self.apic_id & CLUSTER_ID_MASK) >> 4;
        self.set_reg(APIC_OFFSET_ID, self.apic_id);
        self.set_reg(APIC_OFFSET_LDR, (cluster_id << 16) | (1 << logical_id));
    }

    pub fn get_apicbase(&self) -> u64 {
        self.regs.apic_base
    }

    pub fn set_apicbase(&mut self, new: u64) -> Result<(), TdxError> {
        if new & APICBASE_RESERVED != 0 {
            return Err(TdxError::InjectExcp(ErrExcp::GP(0)));
        }
        let old_apic_base = self.get_apicbase();
        if old_apic_base != new {
            let changed = old_apic_base ^ new;
            /* Logic to check for change in Bits 11:10 for vLAPIC mode switch */
            if (changed & APICBASE_LAPIC_MODE) != 0 {
                let mode = new & APICBASE_LAPIC_MODE;
                if mode == APICBASE_X2APIC {
                    // Invalid lapic mode
                    return Err(TdxError::InjectExcp(ErrExcp::GP(0)));
                } else if mode == (APICBASE_XAPIC | APICBASE_X2APIC) {
                    self.regs.apic_base = new;
                    self.build_x2apic_id();
                    this_vcpu_mut(self.vm_id).get_ctx_mut().set_intr_status(0);
                    this_vcpu(self.vm_id)
                        .get_cb()
                        .make_request(VcpuReqFlags::EN_X2APICV);
                } else {
                    // TODO: Logic to check mode switch according to SDM 10.12.5
                }
            }
            // TODO: Logic to check for change in Bits 35:12 and Bit 7 and emulate
        }

        Ok(())
    }
}
