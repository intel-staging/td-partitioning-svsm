// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

extern crate alloc;

use super::error::{ErrExcp, TdxError};
use super::percpu::{this_vcpu, this_vcpu_mut};
use super::tdcall::tdvmcall_wrmsr;
use super::tdp::{get_vcpu_cb, get_vcpu_cbs, this_tdp};
use super::utils::TdpVmId;
use super::vcpu::ResetMode;
use super::vcpu_comm::{VcpuCommBlock, VcpuReqFlags, VcpuStateReq};
use super::vmcs_lib::{VmcsField32Control, VmcsField64Control, VMX_INT_INFO_VALID};
use crate::address::{PhysAddr, VirtAddr};
use crate::cpu::idt::common::FIRST_DYNAMIC_VECTOR;
use crate::cpu::msr::{rdtsc, MSR_IA32_TSC_DEADLINE};
use crate::locking::SpinLock;
use crate::mm::alloc::allocate_zeroed_page;
use crate::mm::{virt_to_phys, PAGE_SIZE};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// APIC Registers
const APIC_OFFSET_ID: u32 = 0x20; // Local APIC ID
const APIC_OFFSET_VER: u32 = 0x30; // Local APIC Version
const APIC_OFFSET_TPR: u32 = 0x80; // Task Priority Register
const APIC_OFFSET_PPR: u32 = 0xA0; // Processor Priority Register
const APIC_OFFSET_EOI: u32 = 0xB0; // EOI Register
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
const APIC_OFFSET_TIMER_CCR: u32 = 0x390; // Timer's Current Count
const APIC_OFFSET_TIMER_DCR: u32 = 0x3E0; // Timer's Divide Configuration
const APIC_OFFSET_SELF_IPI: u32 = 0x3F0; // Self IPI Register

// constants relating to APIC ID registers
const APIC_ID_SHIFT: u32 = 24;

// fields in VER
const MAXLVTSHIFT: u32 = 16;

// fields in LDR
const APIC_LDR_RESERVED: u32 = 0x00ffffff;

// fields in DFR
const APIC_DFR_RESERVED: u32 = 0x0fffffff;
const APIC_DFR_MODEL_MASK: u32 = 0xf0000000;
const APIC_DFR_MODEL_FLAT: u32 = 0xf0000000;
const APIC_DFR_MODEL_CLUSTER: u32 = 0x00000000;

// fields in SVR
const APIC_SVR_VECTOR: u32 = 0x000000ff;
const APIC_SVR_ENABLE: u32 = 0x00000100;

// fields in ESR
const APIC_ESR_SEND_ILLEGAL_VECTOR: u32 = 0x00000020;
const APIC_ESR_RECEIVE_ILLEGAL_VECTOR: u32 = 0x00000040;

// fields in ICR_LOW
const APIC_VECTOR_MASK: u32 = 0x000000ff;

const APIC_DELMODE_MASK: u32 = 0x00000700;
const APIC_DELMODE_FIXED: u32 = 0x00000000;
const APIC_DELMODE_NMI: u32 = 0x00000400;
const APIC_DELMODE_INIT: u32 = 0x00000500;
const APIC_DELMODE_STARTUP: u32 = 0x00000600;
const APIC_DELSTAT_PEND: u32 = 0x00001000;
const APIC_DEST_MASK: u32 = 0x000c0000;
const APIC_DEST_NOSHORT: u32 = 0x00000000;
const APIC_DEST_SELF: u32 = 0x00040000;
const APIC_DEST_ALLISELF: u32 = 0x00080000;
const APIC_DEST_ALLESELF: u32 = 0x000c0000;
const APIC_DESTMODE_LOG: u32 = 0x00000800;
const APIC_LEVEL_MASK: u32 = 0x00004000;
const APIC_LEVEL_DEASSERT: u32 = 0x00000000;

// fields in LVT1/2
const APIC_LVT_VECTOR: u32 = 0x000000ff;
const APIC_LVT_DM: u32 = 0x00000700;
const APIC_LVT_DS: u32 = 0x00001000;
const APIC_LVT_IIPP: u32 = 0x00002000;
const APIC_LVT_RIRR: u32 = 0x00004000;
const APIC_LVT_TM: u32 = 0x00008000;
const APIC_LVT_M: u32 = 0x00010000;

// fields in LVT Timer
const APIC_LVTT_VECTOR: u32 = 0x000000ff;
const APIC_LVTT_M: u32 = 0x00010000;
const APIC_LVTT_TM: u32 = 0x00060000;
const APIC_LVTT_TM_PERIODIC: u32 = 0x00020000;
const APIC_LVTT_TM_TSCDLT: u32 = 0x00040000;

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

    fn clear_isr(&mut self, idx: usize, val: u32) {
        let apic_page = self.reg_page_mut();
        apic_page.isr[idx].v &= !val;
    }

    fn test_and_set_tmr(&mut self, idx: usize, val: u32) -> bool {
        let apic_page = self.reg_page_mut();
        let old_v = apic_page.tmr[idx].v;
        apic_page.tmr[idx].v |= val;
        (old_v & val) != 0
    }

    fn test_and_clear_tmr(&mut self, idx: usize, val: u32) -> bool {
        let apic_page = self.reg_page_mut();
        let old_v = apic_page.tmr[idx].v;
        apic_page.tmr[idx].v &= !val;
        (old_v & val) != 0
    }

    fn test_and_set_irr(&mut self, idx: usize, val: u32) -> bool {
        let apic_page = self.reg_page_mut();
        let old_v = apic_page.irr[idx].v;
        apic_page.irr[idx].v |= val;
        (old_v & val) != 0
    }

    fn set_irr(&mut self, idx: usize, val: u32) {
        let apic_page = self.reg_page_mut();
        apic_page.irr[idx].v |= val;
    }

    fn clear_irr(&mut self, idx: usize, val: u32) {
        let apic_page = self.reg_page_mut();
        apic_page.irr[idx].v &= !val;
    }
}

pub trait VlapicRegsRead: Sync + Send + core::fmt::Debug {
    fn get_reg(&self, offset: u32) -> u32;
    fn is_x2apic(&self) -> bool;
}

impl VlapicRegsRead for SpinLock<VlapicRegs> {
    fn get_reg(&self, offset: u32) -> u32 {
        self.lock().get_reg(offset)
    }

    fn is_x2apic(&self) -> bool {
        self.lock().is_x2apic()
    }
}

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

fn start_tsc_deadline_timer(timeout: u64) {
    tdvmcall_wrmsr(MSR_IA32_TSC_DEADLINE, timeout).unwrap();
}

fn x2apic_msr_to_regoff(msr: u32) -> u32 {
    ((msr - 0x800) & 0x3ff) << 4
}

fn vector_prio(vector: u8) -> u8 {
    vector >> 4
}

fn vlapic_dest_match(vlapic: &Arc<dyn VlapicRegsRead>, dest: u32) -> bool {
    let logical_id: u32;
    let cluster_id: u32;
    let dest_logical_id: u32;
    let dest_cluster_id: u32;
    let ldr = vlapic.get_reg(APIC_OFFSET_LDR);
    if vlapic.is_x2apic() {
        logical_id = ldr & 0xFFFF;
        cluster_id = (ldr >> 16) & 0xFFFF;
        dest_logical_id = dest & 0xFFFF;
        dest_cluster_id = (dest >> 16) & 0xFFFF;
        if (cluster_id == dest_cluster_id) && ((logical_id & dest_logical_id) != 0) {
            return true;
        }
    } else {
        let dfr = vlapic.get_reg(APIC_OFFSET_DFR);
        if (dfr & APIC_DFR_MODEL_MASK) == APIC_DFR_MODEL_FLAT {
            // In the "Flat Model" the MDA is interpreted as an 8-bit wide
            // bitmask. This model is available in the xAPIC mode only.
            logical_id = ldr >> 24;
            dest_logical_id = dest & 0xff;
            if (logical_id & dest_logical_id) != 0 {
                return true;
            }
        } else if (dfr & APIC_DFR_MODEL_MASK) == APIC_DFR_MODEL_CLUSTER {
            // In the "Cluster Model" the MDA is used to identify a
            // specific cluster and a set of APICs in that cluster.
            logical_id = (ldr >> 24) & 0xf;
            cluster_id = ldr >> 28;
            dest_logical_id = dest & 0xf;
            dest_cluster_id = (dest >> 4) & 0xf;
            if (cluster_id == dest_cluster_id) && ((logical_id & dest_logical_id) != 0) {
                return true;
            }
        } else {
            // Guest has configured a bad logical model for this vcpu.
            log::warn!("vlapic has bad logical model {:#018x}", dfr);
        }
    }

    false
}

fn vlapic_calc_dest_noshort(
    vm_id: TdpVmId,
    is_broadcast: bool,
    dest: u32,
    phys: bool,
    lowprio: bool,
) -> Vec<Arc<VcpuCommBlock>> {
    let cbs: Vec<Arc<VcpuCommBlock>> = get_vcpu_cbs(vm_id).map_or(Vec::new(), |cbs| {
        cbs.iter()
            .filter_map(|(&apic_id, cb)| {
                if is_broadcast {
                    Some(cb.clone())
                } else if phys {
                    // Physical mode: "dest" is local APIC ID
                    if apic_id == dest {
                        Some(cb.clone())
                    } else {
                        None
                    }
                } else if vlapic_dest_match(&cb.vlapic, dest) {
                    // Logical mode: "dest" is message destination addr
                    //to be compared with the logical APIC ID in LDR.
                    Some(cb.clone())
                } else {
                    None
                }
            })
            .collect()
    });

    if !cbs.is_empty() && !is_broadcast && !phys && lowprio {
        // Find out the lowest for logical mode if lowprio is true
        let mut lowest_cb = &cbs[0];
        let mut lowest_ppr = cbs[0].vlapic.get_reg(APIC_OFFSET_PPR);

        for cb in cbs.iter().skip(1) {
            let ppr = cb.vlapic.get_reg(APIC_OFFSET_PPR);
            if lowest_ppr > ppr {
                lowest_cb = cb;
                lowest_ppr = ppr;
            }
        }
        alloc::vec![lowest_cb.clone()]
    } else {
        cbs
    }
}

fn active_vcpus(vm_id: TdpVmId, ex_self: Option<u32>) -> Vec<Arc<VcpuCommBlock>> {
    get_vcpu_cbs(vm_id).map_or(Vec::new(), |cbs| {
        cbs.iter()
            .filter_map(|(&apic_id, cb)| {
                if let Some(ex_self_apic_id) = ex_self {
                    if apic_id != ex_self_apic_id {
                        Some(cb.clone())
                    } else {
                        None
                    }
                } else {
                    Some(cb.clone())
                }
            })
            .collect()
    })
}

fn vlapic_calc_dest(
    vm_id: TdpVmId,
    shorthand: u32,
    is_broadcast: bool,
    dest: u32,
    phys: bool,
    lowprio: bool,
) -> Vec<Arc<VcpuCommBlock>> {
    match shorthand {
        APIC_DEST_NOSHORT => vlapic_calc_dest_noshort(vm_id, is_broadcast, dest, phys, lowprio),
        APIC_DEST_SELF => {
            get_vcpu_cb(vm_id, this_vcpu(vm_id).apic_id()).map_or(Vec::new(), |cb| alloc::vec![cb])
        }
        APIC_DEST_ALLISELF => active_vcpus(vm_id, None),
        APIC_DEST_ALLESELF => active_vcpus(vm_id, Some(this_vcpu(vm_id).apic_id())),
        _ => {
            panic!("calc_dest: not support shorthand {}", shorthand);
        }
    }
}

pub struct Vlapic {
    vm_id: TdpVmId,
    apic_id: u32,
    is_bsp: bool,
    regs: Arc<SpinLock<VlapicRegs>>,
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
        let regs = Arc::new(SpinLock::new(VlapicRegs::new(DEFAULT_APIC_BASE)));
        unsafe { core::ptr::write(core::ptr::addr_of_mut!(self.regs), regs) };
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
        self.regs.lock().apic_base = DEFAULT_APIC_BASE;
        if self.is_bsp {
            self.regs.lock().apic_base |= APICBASE_BSP;
        }
        if mode == ResetMode::InitReset {
            if (preserved_lapic_mode & APICBASE_ENABLED) != 0 {
                // Per SDM 10.12.5.1 vol.3, need to preserve lapic mode after INIT
                self.regs.lock().apic_base |= preserved_lapic_mode;
            }
        } else {
            // Upon reset, vlapic is set to xAPIC mode.
            self.regs.lock().apic_base |= APICBASE_XAPIC;
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
        virt_to_phys(self.regs.lock().apic_page)
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

    fn set_eoi_exit_bitmap(&mut self, vector: u8) {
        let vec_mask = 1u64 << (vector & 0x3f);
        let idx = (vector as usize) >> 6;
        if (self.eoi_exit_bitmap[idx].fetch_or(vec_mask, Ordering::AcqRel) & vec_mask) == 0 {
            self.set_vmcs_eoi_exit_bitmap();
        }
    }

    fn clear_eoi_exit_bitmap(&mut self, vector: u8) {
        let vec_mask = 1u64 << (vector & 0x3f);
        let idx = (vector as usize) >> 6;
        if (self.eoi_exit_bitmap[idx].fetch_and(!vec_mask, Ordering::AcqRel) & vec_mask) != 0 {
            self.set_vmcs_eoi_exit_bitmap();
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
        self.regs.lock().get_reg(offset)
    }

    #[inline(always)]
    fn set_reg(&mut self, offset: u32, val: u32) {
        self.regs.lock().set_reg(offset, val);
    }

    #[inline(always)]
    fn is_x2apic(&self) -> bool {
        self.regs.lock().is_x2apic()
    }

    fn build_x2apic_id(&mut self) {
        let logical_id = self.apic_id & LOGICAL_ID_MASK;
        let cluster_id = (self.apic_id & CLUSTER_ID_MASK) >> 4;
        self.set_reg(APIC_OFFSET_ID, self.apic_id);
        self.set_reg(APIC_OFFSET_LDR, (cluster_id << 16) | (1 << logical_id));
    }

    pub fn get_apicbase(&self) -> u64 {
        self.regs.lock().apic_base
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
                    self.regs.lock().apic_base = new;
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

    fn lvtt_is_tsc_deadline(&self) -> bool {
        self.get_reg(APIC_OFFSET_TIMER_LVT) & APIC_LVTT_TM == APIC_LVTT_TM_TSCDLT
    }

    fn lvtt_is_period(&self) -> bool {
        self.get_reg(APIC_OFFSET_TIMER_LVT) & APIC_LVTT_TM == APIC_LVTT_TM_PERIODIC
    }

    fn lvtt_masked(&self) -> bool {
        self.get_reg(APIC_OFFSET_TIMER_LVT) & APIC_LVTT_M != 0
    }

    fn set_expiration(&mut self) -> bool {
        let tmicr = self.vtimer.tmicr;
        let divisor_shift = self.vtimer.divisor_shift;
        if (tmicr == 0) || (divisor_shift > 8) {
            false
        } else {
            let delta = (tmicr as u64) << divisor_shift;
            let period = if !self.lvtt_is_period() { 0 } else { delta };
            self.update_timer(rdtsc() + delta, period);
            true
        }
    }

    fn timer_expired(&self, now: u64) -> Option<u64> {
        if (self.vtimer.timeout != 0) && (now < self.vtimer.timeout) {
            // If not expired, return option contains timer delta
            Some(self.vtimer.timeout - now)
        } else {
            // return None if expired
            None
        }
    }

    fn get_ccr(&self) -> u32 {
        if (self.vtimer.tmicr != 0) && !self.lvtt_is_tsc_deadline() {
            if let Some(delta) = self.timer_expired(rdtsc()) {
                return (delta >> self.vtimer.divisor_shift) as u32;
            }
        }
        0
    }

    fn update_ppr(&mut self) {
        let tpr = self.get_reg(APIC_OFFSET_TPR) as u8;
        let ppr = if vector_prio(tpr) >= vector_prio(self.in_service_vec) {
            tpr
        } else {
            self.in_service_vec & 0xf0
        };

        self.set_reg(APIC_OFFSET_PPR, ppr as u32);
    }

    fn find_highest_isr(&self) -> u8 {
        for i in (0..8).rev() {
            let val = self.get_reg(APIC_OFFSET_ISR0 + i * 16);
            if val != 0 {
                let bitpos = 31 - val.leading_zeros();
                return (32 * i + bitpos) as u8;
            }
        }
        0
    }

    fn write_eoi(&mut self) {
        if self.in_service_vec != 0 {
            let vec_mask = 1u32 << (self.in_service_vec & 0x1f);
            let idx = (self.in_service_vec >> 5) as usize;
            // clear isr
            self.regs.lock().clear_isr(idx, vec_mask);
            self.in_service_vec = self.find_highest_isr();
            self.update_ppr();
            if (self.get_reg(APIC_OFFSET_TMR0 + idx as u32 * 16) & vec_mask) != 0 {
                this_tdp(self.vm_id)
                    .get_vioapic()
                    .broadcast_eoi(self.in_service_vec)
                    .expect("Failed to broadcase EOI");
            }
        }
    }

    fn write_svr(&mut self, new: u32) {
        let old = self.get_reg(APIC_OFFSET_SVR);
        self.set_reg(APIC_OFFSET_SVR, new);
        if ((old ^ new) & APIC_SVR_ENABLE) != 0 {
            if (new & APIC_SVR_ENABLE) == 0 {
                stop_tsc_deadline_timer();
                self.mask_lvts();
            } else if self.lvtt_is_period() && self.set_expiration() {
                start_tsc_deadline_timer(self.vtimer.timeout);
            }
        }
    }

    fn write_esr(&mut self) {
        self.set_reg(APIC_OFFSET_ESR, self.esr_pending);
        self.esr_pending = 0;
    }

    fn set_pir(&mut self, vector: u8) {
        let vec_mask = 1u64 << (vector & 0x3f);
        let idx = (vector as usize) >> 6;
        self.pir[idx].fetch_or(vec_mask, Ordering::AcqRel);
    }

    fn set_irr(&mut self, vector: u8) -> bool {
        let vec_mask = 1u32 << (vector & 0x1f);
        let idx = (vector as usize) >> 5;
        // True will be returned if IRR was not set previously.
        // Otherwise false will be returned.
        self.regs.lock().test_and_set_irr(idx, vec_mask)
    }

    /* we only set eoi exit bitmap under x2apic mode when VID enabled */
    fn set_tmr(&mut self, vector: u8, level: bool) {
        let vec_mask = 1u32 << (vector & 0x1f);
        let tmr_idx = (vector as usize) >> 5;
        if level {
            if !self.regs.lock().test_and_set_tmr(tmr_idx, vec_mask) && self.is_x2apic() {
                self.set_eoi_exit_bitmap(vector);
            }
        } else if self.regs.lock().test_and_clear_tmr(tmr_idx, vec_mask) && self.is_x2apic() {
            self.clear_eoi_exit_bitmap(vector);
        }
    }

    // xapic:  accept intr by set irr
    // x2apic: accept intr by set pir
    fn accept_intr(&mut self, vector: u8, level: bool) {
        if self.is_x2apic() {
            // update TMR if interrupt trigger mode has changed
            self.set_tmr(vector, level);
            self.set_pir(vector);
        } else if self.set_irr(vector) {
            // xapic should not trigger EOI bitmap update
            self.set_tmr(vector, level);
        }

        this_vcpu(self.vm_id)
            .get_cb()
            .make_request(VcpuReqFlags::REQ_EVENT);
    }

    fn set_error(&mut self, err_mask: u32) {
        self.esr_pending |= err_mask;
        if !self.esr_firing.fetch_or(true, Ordering::AcqRel) {
            let lvt = self.get_reg(APIC_OFFSET_ERROR_LVT);
            if (lvt & APIC_LVT_M) == 0 {
                let vec = (lvt & APIC_LVT_VECTOR) as u8;
                if vec >= 16 {
                    self.accept_intr(vec, false);
                }
            }
            self.esr_firing.store(false, Ordering::Release);
        }
    }

    pub fn set_intr(&mut self, vector: u8, level: bool) {
        if vector < 16 {
            self.set_error(APIC_ESR_RECEIVE_ILLEGAL_VECTOR);
        } else {
            self.accept_intr(vector, level);
        }
    }

    fn write_icrlo(&mut self, new: u32) {
        self.set_reg(APIC_OFFSET_ICR_LOW, new & !APIC_DELSTAT_PEND);
        let icr_low = self.get_reg(APIC_OFFSET_ICR_LOW);
        let vec = (icr_low & APIC_VECTOR_MASK) as u8;
        let mode = icr_low & APIC_DELMODE_MASK;
        let shorthand = icr_low & APIC_DEST_MASK;
        let phys = (icr_low & APIC_DESTMODE_LOG) == 0;
        let icr_high = self.get_reg(APIC_OFFSET_ICR_HI);
        let (dest, is_broadcast) = if self.is_x2apic() {
            (icr_high, icr_high == 0xffffffff)
        } else {
            let dest = icr_high >> APIC_ID_SHIFT;
            (dest, dest == 0xff)
        };

        if (mode == APIC_DELMODE_FIXED) && (vec < 16) {
            self.set_error(APIC_ESR_SEND_ILLEGAL_VECTOR);
        } else {
            let cbs = vlapic_calc_dest(self.vm_id, shorthand, is_broadcast, dest, phys, false);
            for cb in cbs {
                match mode {
                    APIC_DELMODE_FIXED => cb.make_pending_virq(vec, false),
                    APIC_DELMODE_NMI => cb.make_request(VcpuReqFlags::INJ_NMI),
                    APIC_DELMODE_INIT => {
                        if cb.apic_id == self.apic_id {
                            log::warn!("vlapic: Not support sending INIT to self");
                        } else if (icr_low & APIC_LEVEL_MASK) != APIC_LEVEL_DEASSERT {
                            cb.make_pending_state(VcpuStateReq::Init);
                        }
                    }
                    APIC_DELMODE_STARTUP => {
                        if cb.apic_id == self.apic_id {
                            log::warn!("vlapic: Not support sending SIPI to self");
                        } else {
                            cb.make_pending_state(VcpuStateReq::Sipi {
                                entry: ((icr_low & APIC_VECTOR_MASK) << 12) as u64,
                            });
                        }
                    }
                    _ => log::warn!("vlapic: unsupported deliver mode 0x{:x}", mode),
                }
            }
        }
    }

    fn write_icrtmr(&mut self, new: u32) {
        if !self.lvtt_is_tsc_deadline() {
            self.set_reg(APIC_OFFSET_TIMER_ICR, new);
            self.vtimer.tmicr = new;
            if self.set_expiration() {
                start_tsc_deadline_timer(self.vtimer.timeout);
            } else {
                stop_tsc_deadline_timer();
            }
        }
    }

    fn enabled(&self) -> bool {
        (self.get_apicbase() & APICBASE_ENABLED != 0)
            && (self.get_reg(APIC_OFFSET_SVR) & APIC_SVR_ENABLE != 0)
    }

    fn sync_pir_to_irr(&mut self) {
        for i in 0..4 {
            let val = self.pir[i].load(Ordering::Acquire);
            if val != 0 {
                self.regs.lock().set_irr(i * 2, (val & 0xffff_ffff) as u32);
                self.regs
                    .lock()
                    .set_irr(i * 2 + 1, ((val >> 32) & 0xffff_ffff) as u32);
                self.pir[i].store(0, Ordering::Release);
            }
        }
    }

    fn find_highest_irr(&self) -> u8 {
        for i in (0..8).rev() {
            let val = self.get_reg(APIC_OFFSET_IRR0 + i * 16);
            if val != 0 {
                let bitpos = 31 - val.leading_zeros();
                return (32 * i + bitpos) as u8;
            }
        }
        0
    }

    fn find_deliverable_intr(&self) -> u8 {
        let vector = self.find_highest_irr();
        if vector_prio(vector) > vector_prio(self.get_reg(APIC_OFFSET_PPR) as u8) {
            vector
        } else {
            0
        }
    }

    fn update_irr_isr_ppr(&mut self, vector: u8) {
        let vec_mask = 1u32 << (vector & 0x1f);
        let idx = (vector as usize) >> 5;
        // clear irr
        self.regs.lock().clear_irr(idx, vec_mask);
        // set isr
        self.regs.lock().clear_isr(idx, vec_mask);
        self.update_ppr();
    }

    fn update_tpr_threshold(&self) {
        let tpr = (self.get_reg(APIC_OFFSET_TPR) as u8) >> 4;
        let irr = self.find_highest_irr() >> 4;
        let mut threshold = if irr > tpr { 0 } else { irr };

        // SDM vol-3 27.2.1.1 Checks on VMX Controls -> VM-Excution Control Fields:
        // The following check is performed if the “use TPR shadow” VM-execution control is 1 and
        // the “virtualize APIC accesses” and “virtual-interrupt delivery” VM-execution controls
        // are both 0: the value of bits 3:0 of the TPR threshold VM-execution control field
        // should not be greater than the value of bits 7:4 of VTPR (see Section 30.1.1).
        //
        // under xapic mode, we always disalble virtual APIC access & virtual interrupt delivery,
        // and may enable TPR shadowing, then we must ensure TPR[7:4] >= TPR_THRESHOLD[3:0]
        if vector_prio(tpr) < threshold {
            threshold = vector_prio(tpr);
        }

        assert!(threshold < 16);
        this_vcpu(self.vm_id)
            .get_vmcs()
            .write32(VmcsField32Control::TPR_THRESHOLD, threshold as u32);
    }

    // xapic:  TPR shadow
    //         trap all read
    // x2apic: TPR shadow + virtual interrupt delivery + APIC register virtualization
    //         trap read only for TIMER_CCR & CMCI_LVT
    pub fn read_reg(&self, offset_arg: u32) -> Result<u32, TdxError> {
        let val = if !self.is_x2apic() {
            match offset_arg {
                APIC_OFFSET_ID => self.get_reg(APIC_OFFSET_ID),
                APIC_OFFSET_VER => self.get_reg(APIC_OFFSET_VER),
                APIC_OFFSET_TPR => self.get_reg(APIC_OFFSET_TPR),
                APIC_OFFSET_PPR => self.get_reg(APIC_OFFSET_PPR),
                APIC_OFFSET_LDR => self.get_reg(APIC_OFFSET_LDR),
                APIC_OFFSET_DFR => self.get_reg(APIC_OFFSET_DFR),
                APIC_OFFSET_SVR => self.get_reg(APIC_OFFSET_SVR),
                APIC_OFFSET_ISR0 => self.get_reg(APIC_OFFSET_ISR0),
                APIC_OFFSET_ISR1 => self.get_reg(APIC_OFFSET_ISR1),
                APIC_OFFSET_ISR2 => self.get_reg(APIC_OFFSET_ISR2),
                APIC_OFFSET_ISR3 => self.get_reg(APIC_OFFSET_ISR3),
                APIC_OFFSET_ISR4 => self.get_reg(APIC_OFFSET_ISR4),
                APIC_OFFSET_ISR5 => self.get_reg(APIC_OFFSET_ISR5),
                APIC_OFFSET_ISR6 => self.get_reg(APIC_OFFSET_ISR6),
                APIC_OFFSET_ISR7 => self.get_reg(APIC_OFFSET_ISR7),
                APIC_OFFSET_TMR0 => self.get_reg(APIC_OFFSET_TMR0),
                APIC_OFFSET_TMR1 => self.get_reg(APIC_OFFSET_TMR1),
                APIC_OFFSET_TMR2 => self.get_reg(APIC_OFFSET_TMR2),
                APIC_OFFSET_TMR3 => self.get_reg(APIC_OFFSET_TMR3),
                APIC_OFFSET_TMR4 => self.get_reg(APIC_OFFSET_TMR4),
                APIC_OFFSET_TMR5 => self.get_reg(APIC_OFFSET_TMR5),
                APIC_OFFSET_TMR6 => self.get_reg(APIC_OFFSET_TMR6),
                APIC_OFFSET_TMR7 => self.get_reg(APIC_OFFSET_TMR7),
                APIC_OFFSET_IRR0 => self.get_reg(APIC_OFFSET_IRR0),
                APIC_OFFSET_IRR1 => self.get_reg(APIC_OFFSET_IRR1),
                APIC_OFFSET_IRR2 => self.get_reg(APIC_OFFSET_IRR2),
                APIC_OFFSET_IRR3 => self.get_reg(APIC_OFFSET_IRR3),
                APIC_OFFSET_IRR4 => self.get_reg(APIC_OFFSET_IRR4),
                APIC_OFFSET_IRR5 => self.get_reg(APIC_OFFSET_IRR5),
                APIC_OFFSET_IRR6 => self.get_reg(APIC_OFFSET_IRR6),
                APIC_OFFSET_IRR7 => self.get_reg(APIC_OFFSET_IRR7),
                APIC_OFFSET_ESR => self.get_reg(APIC_OFFSET_ESR),
                APIC_OFFSET_ICR_LOW => self.get_reg(APIC_OFFSET_ICR_LOW),
                APIC_OFFSET_ICR_HI => self.get_reg(APIC_OFFSET_ICR_HI),
                APIC_OFFSET_CMCI_LVT => self.get_reg(APIC_OFFSET_CMCI_LVT),
                APIC_OFFSET_TIMER_LVT => self.get_reg(APIC_OFFSET_TIMER_LVT),
                APIC_OFFSET_THERM_LVT => self.get_reg(APIC_OFFSET_THERM_LVT),
                APIC_OFFSET_PERF_LVT => self.get_reg(APIC_OFFSET_PERF_LVT),
                APIC_OFFSET_LINT0_LVT => self.get_reg(APIC_OFFSET_LINT0_LVT),
                APIC_OFFSET_LINT1_LVT => self.get_reg(APIC_OFFSET_LINT1_LVT),
                APIC_OFFSET_ERROR_LVT => self.get_reg(APIC_OFFSET_ERROR_LVT),
                APIC_OFFSET_TIMER_ICR => {
                    if self.lvtt_is_tsc_deadline() {
                        0
                    } else {
                        self.get_reg(APIC_OFFSET_TIMER_ICR)
                    }
                }
                APIC_OFFSET_TIMER_CCR => self.get_ccr(),
                APIC_OFFSET_TIMER_DCR => self.get_reg(APIC_OFFSET_TIMER_DCR),
                _ => return Err(TdxError::Vlapic),
            }
        } else {
            match x2apic_msr_to_regoff(offset_arg) {
                APIC_OFFSET_ID => self.get_reg(APIC_OFFSET_ID),
                APIC_OFFSET_VER => self.get_reg(APIC_OFFSET_VER),
                APIC_OFFSET_LDR => self.get_reg(APIC_OFFSET_LDR),
                APIC_OFFSET_SVR => self.get_reg(APIC_OFFSET_SVR),
                APIC_OFFSET_ESR => self.get_reg(APIC_OFFSET_ESR),
                APIC_OFFSET_ICR_LOW => self.get_reg(APIC_OFFSET_ICR_LOW),
                APIC_OFFSET_CMCI_LVT => self.get_reg(APIC_OFFSET_CMCI_LVT),
                APIC_OFFSET_TIMER_LVT => self.get_reg(APIC_OFFSET_TIMER_LVT),
                APIC_OFFSET_THERM_LVT => self.get_reg(APIC_OFFSET_THERM_LVT),
                APIC_OFFSET_PERF_LVT => self.get_reg(APIC_OFFSET_PERF_LVT),
                APIC_OFFSET_LINT0_LVT => self.get_reg(APIC_OFFSET_LINT0_LVT),
                APIC_OFFSET_LINT1_LVT => self.get_reg(APIC_OFFSET_LINT1_LVT),
                APIC_OFFSET_ERROR_LVT => self.get_reg(APIC_OFFSET_ERROR_LVT),
                APIC_OFFSET_TIMER_ICR => {
                    if self.lvtt_is_tsc_deadline() {
                        0
                    } else {
                        self.get_reg(APIC_OFFSET_TIMER_ICR)
                    }
                }
                APIC_OFFSET_TIMER_CCR => self.get_ccr(),
                APIC_OFFSET_TIMER_DCR => self.get_reg(APIC_OFFSET_TIMER_DCR),
                _ => return Err(TdxError::Vlapic),
            }
        };

        Ok(val)
    }

    // xapic:  TPR shadow
    //         trap all write except SELF_IPI
    // x2apic: TPR shadow + virtual interrupt delivery + APIC register virtualization
    //         trap all write except DFR & ICR_HI
    pub fn write_reg(&mut self, offset_arg: u32, data: u64) -> Result<(), TdxError> {
        let data32 = data as u32;
        let data32_high = (data >> 32) as u32;
        let is_x2apic = self.is_x2apic();
        let offset = if is_x2apic {
            x2apic_msr_to_regoff(offset_arg)
        } else {
            offset_arg
        };

        match offset {
            APIC_OFFSET_ID => {} // Force APIC ID as read only
            APIC_OFFSET_TPR => {
                if !is_x2apic {
                    self.set_reg(APIC_OFFSET_TPR, data32);
                    self.update_ppr();
                } else {
                    return Err(TdxError::Vlapic);
                }
            }
            APIC_OFFSET_EOI => self.write_eoi(),
            APIC_OFFSET_LDR => self.set_reg(APIC_OFFSET_LDR, data32 & !APIC_LDR_RESERVED),
            APIC_OFFSET_DFR => {
                if !is_x2apic {
                    self.set_reg(
                        APIC_OFFSET_DFR,
                        data32 & APIC_DFR_MODEL_MASK | APIC_DFR_RESERVED,
                    );
                } else {
                    return Err(TdxError::Vlapic);
                }
            }
            APIC_OFFSET_SVR => self.write_svr(data32),
            APIC_OFFSET_ESR => self.write_esr(),
            APIC_OFFSET_ICR_LOW => {
                if is_x2apic {
                    self.set_reg(APIC_OFFSET_ICR_HI, data32_high);
                }
                self.write_icrlo(data32);
            }
            APIC_OFFSET_ICR_HI => {
                if !is_x2apic {
                    self.set_reg(APIC_OFFSET_ICR_HI, data32);
                } else {
                    return Err(TdxError::Vlapic);
                }
            }
            APIC_OFFSET_CMCI_LVT => self.write_lvt(APIC_OFFSET_CMCI_LVT, data32),
            APIC_OFFSET_TIMER_LVT => self.write_lvt(APIC_OFFSET_TIMER_LVT, data32),
            APIC_OFFSET_THERM_LVT => self.write_lvt(APIC_OFFSET_THERM_LVT, data32),
            APIC_OFFSET_PERF_LVT => self.write_lvt(APIC_OFFSET_PERF_LVT, data32),
            APIC_OFFSET_LINT0_LVT => self.write_lvt(APIC_OFFSET_LINT0_LVT, data32),
            APIC_OFFSET_LINT1_LVT => self.write_lvt(APIC_OFFSET_LINT1_LVT, data32),
            APIC_OFFSET_ERROR_LVT => self.write_lvt(APIC_OFFSET_ERROR_LVT, data32),
            APIC_OFFSET_TIMER_ICR => self.write_icrtmr(data32),
            APIC_OFFSET_TIMER_DCR => self.write_dcr(data32),
            APIC_OFFSET_SELF_IPI => {
                if is_x2apic {
                    self.set_reg(APIC_OFFSET_SELF_IPI, data32);
                    let vec = (data32 & APIC_VECTOR_MASK) as u8;
                    if vec < 16 {
                        self.set_error(APIC_ESR_SEND_ILLEGAL_VECTOR);
                    } else {
                        self.accept_intr(vec, false);
                    }
                } else {
                    return Err(TdxError::Vlapic);
                }
            }
            _ => return Err(TdxError::Vlapic),
        }
        Ok(())
    }

    pub fn get_tsc_deadline_msr<F: Fn() -> u64>(&self, get_dlt: F) -> u64 {
        if !self.lvtt_is_tsc_deadline() || self.timer_expired(rdtsc()).is_none() {
            0u64
        } else {
            get_dlt()
        }
    }

    pub fn set_tsc_deadline_msr<F: FnMut(u64)>(&mut self, val: u64, mut set_dlt: F) {
        if self.lvtt_is_tsc_deadline() {
            set_dlt(val);
            if val != 0 {
                let timeout = val
                    - this_vcpu(self.vm_id)
                        .get_vmcs()
                        .read64(VmcsField64Control::TSC_OFFSET);
                self.update_timer(timeout, 0);
                start_tsc_deadline_timer(self.vtimer.timeout);
            } else {
                self.update_timer(0, 0);
                stop_tsc_deadline_timer();
            }
        }
    }

    pub fn handle_expired_timer(&mut self) {
        // inject vcpu timer interrupt if not masked
        if !self.lvtt_masked() {
            self.set_intr(
                (self.get_reg(APIC_OFFSET_TIMER_LVT) & APIC_LVTT_VECTOR) as u8,
                false,
            );
        }

        // restart timer if it is period
        if self.lvtt_is_period() && self.set_expiration() {
            start_tsc_deadline_timer(self.vtimer.timeout);
        }
    }

    // xapic:  inject intr by set int_info vmcs field
    // x2apic: accept intr by set int stat RVI vmcs field
    pub fn inject_intr(&mut self, guest_irq_enabled: bool, injected: bool) {
        if self.enabled() {
            if self.is_x2apic() {
                self.sync_pir_to_irr();
                let vector = self.find_highest_irr();
                if vector != 0 {
                    // write highest vector to RVI(low byte) in guest status field
                    this_vcpu_mut(self.vm_id)
                        .get_ctx_mut()
                        .set_intr_status(vector);
                }
            } else {
                if guest_irq_enabled && !injected {
                    self.update_ppr();
                    let vector = self.find_deliverable_intr();
                    if vector != 0 {
                        this_vcpu(self.vm_id).get_vmcs().write32(
                            VmcsField32Control::VM_ENTRY_INTR_INFO_FIELD,
                            VMX_INT_INFO_VALID | vector as u32,
                        );
                        self.in_service_vec = vector;
                        self.update_irr_isr_ppr(vector);
                    }
                }
                self.update_tpr_threshold();
            }
        }
    }

    // no pending delivery intr for x2apic mode with VID enabled.
    pub fn has_pending_delivery_intr(&mut self) -> bool {
        if self.is_x2apic() {
            false
        } else {
            self.update_ppr();
            if self.find_deliverable_intr() != 0 {
                this_vcpu(self.vm_id)
                    .get_cb()
                    .make_request(VcpuReqFlags::REQ_EVENT);
                true
            } else {
                false
            }
        }
    }

    pub fn has_pending_intr(&self) -> bool {
        self.find_highest_irr() != 0
    }

    pub fn mmio_range(&self) -> (u64, u64) {
        let base = self.get_apicbase() & !((PAGE_SIZE - 1) as u64);
        (base, base + (PAGE_SIZE as u64))
    }

    pub fn apic_id(&self) -> u32 {
        let apic_id = self.get_reg(APIC_OFFSET_ID);
        if self.is_x2apic() {
            apic_id
        } else {
            apic_id >> APIC_ID_SHIFT
        }
    }

    // xapic only
    pub fn read_cr8(&self) -> Result<u64, TdxError> {
        if !self.is_x2apic() {
            Ok(((self.get_reg(APIC_OFFSET_TPR) & 0xf0) >> 4) as u64)
        } else {
            Err(TdxError::Vlapic)
        }
    }

    // xapic only
    pub fn write_cr8(&mut self, cr8: u64) -> Result<(), TdxError> {
        if !self.is_x2apic() {
            self.set_reg(APIC_OFFSET_TPR, ((cr8 & 0x0f) << 4) as u32);
            self.update_ppr();
            Ok(())
        } else {
            Err(TdxError::Vlapic)
        }
    }

    pub fn handle_below_threshold_vmexit(&self) {
        this_vcpu(self.vm_id)
            .get_cb()
            .make_request(VcpuReqFlags::REQ_EVENT);
    }

    pub fn handle_eoi_vmexit(&mut self, vec: u8) {
        let vec_mask = 1u32 << vec;
        let tmr_idx = (vec as u32) >> 5;
        if (self.get_reg(APIC_OFFSET_TMR0 + tmr_idx * 16) & vec_mask) != 0 {
            this_tdp(self.vm_id)
                .get_vioapic()
                .broadcast_eoi(vec)
                .expect("Failed to handle EOI vmexit");
        }
    }

    pub fn regs_reader(&self) -> Arc<dyn VlapicRegsRead> {
        self.regs.clone()
    }
}

const DELMODE_FIXED: u32 = 0x0; // Delivery Mode: Fixed
const DELMODE_LOPRI: u32 = 0x1; // Delivery Mode: Lowest priority
pub fn vlapic_receive_intr(
    vm_id: TdpVmId,
    level: bool,
    dest: u32,
    phys: bool,
    delmode: u32,
    vector: u8,
) {
    assert!(vector >= FIRST_DYNAMIC_VECTOR);
    assert!(delmode == DELMODE_FIXED || delmode == DELMODE_LOPRI);
    let lowprio = delmode == DELMODE_LOPRI;
    let cbs = vlapic_calc_dest_noshort(vm_id, false, dest, phys, lowprio);
    for cb in cbs {
        cb.make_pending_virq(vector, level);
    }
}
