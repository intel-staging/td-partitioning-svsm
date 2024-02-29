// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::features::{cpu_has_feature, X86_FEATURE_X2APIC};
use super::msr::{read_msr, write_msr};
use crate::utils::immut_after_init::ImmutAfterInitCell;

const IA32_APIC_BASE: u32 = 0x1b;
const IA32_X2APIC_APICID: u32 = 0x802;
const IA32_X2APIC_EOI: u32 = 0x80b;
const IA32_X2APIC_SIVR: u32 = 0x80f;
const IA32_X2APIC_ISR0: u32 = 0x810;
const IA32_X2APIC_ISR7: u32 = 0x817;
const IA32_X2APIC_ICR: u32 = 0x830;
const IA32_X2APIC_LVT_TIMER: u32 = 0x832;
const IA32_X2APIC_SELF_IPI: u32 = 0x83f;

const APIC_SVR_ENABLE: u64 = 0x100;
const APIC_SVR_VECTOR: u64 = 0xff;

const APIC_X2APIC_ENABLED: u64 = 1u64 << 10;
const APIC_XAPIC_ENABLED: u64 = 1u64 << 11;

const APIC_ICR_PHYSICAL: u64 = 0u64 << 11;

#[derive(Clone, Copy, Debug)]
pub struct LocalApic;

pub static LAPIC: ImmutAfterInitCell<LocalApic> = ImmutAfterInitCell::new(LocalApic);

#[derive(Clone, Copy, Debug)]
pub enum LvtTimerMode {
    OneShot,
    Periodic,
    TscDeadline,
}

impl From<LvtTimerMode> for u64 {
    fn from(ltm: LvtTimerMode) -> u64 {
        match ltm {
            LvtTimerMode::OneShot => 0,
            LvtTimerMode::Periodic => 1,
            LvtTimerMode::TscDeadline => 2,
        }
    }
}

impl LocalApic {
    pub fn init(&self) {
        assert!(cpu_has_feature(X86_FEATURE_X2APIC));

        let base = read_msr(IA32_APIC_BASE).unwrap();
        if base & APIC_X2APIC_ENABLED == 0 {
            write_msr(
                IA32_APIC_BASE,
                base | APIC_X2APIC_ENABLED | APIC_XAPIC_ENABLED,
            )
            .unwrap();
        }

        write_msr(IA32_X2APIC_SIVR, 0).unwrap();
        // TODO: register spurious-interrupt handler
        write_msr(IA32_X2APIC_SIVR, APIC_SVR_ENABLE | APIC_SVR_VECTOR).unwrap();

        // Make sure ISR is not set
        for isr in (IA32_X2APIC_ISR0..=IA32_X2APIC_ISR7).rev() {
            if read_msr(isr).unwrap() != 0 {
                write_msr(IA32_X2APIC_EOI, 0).unwrap();
            }
        }
    }

    pub fn id(&self) -> u32 {
        read_msr(IA32_X2APIC_APICID).unwrap() as u32
    }

    pub fn eoi(&self) {
        write_msr(IA32_X2APIC_EOI, 0).unwrap();
    }

    pub fn send_ipi(&self, apic_id: u32, vec: u8) {
        if self.id() == apic_id {
            write_msr(IA32_X2APIC_SELF_IPI, vec as u64).unwrap();
        } else {
            let icr = vec as u64 | APIC_ICR_PHYSICAL | ((apic_id as u64) << 32);
            write_msr(IA32_X2APIC_ICR, icr).unwrap();
        }
    }

    pub fn setup_lvt_timer(&self, timer_mode: LvtTimerMode, vec: u8) {
        let val = (u64::from(timer_mode) << 17) | (vec as u64);

        write_msr(IA32_X2APIC_LVT_TIMER, val).unwrap();
    }
}
