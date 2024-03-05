// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author:
//  Chuanxiao Dong <chuanxiao.dong@intel.com>
//  Jason CJ Chen <jason.cj.chen@intel.com>

use super::interrupts::{register_interrupt_handlers, TIMER_VECTOR};
use super::sirte::Sirte;
use super::tdp::init_tdps;
use super::utils::{tdvps_l2_ctls, L2CtlsFlags, TdpVmId, MAX_NUM_L2_VMS};
use super::vcpu::Vcpu;
use crate::address::{Address, VirtAddr};
use crate::cpu::control_regs::{read_cr4, write_cr4, CR4Flags};
use crate::cpu::features::{cpu_has_feature, X86_FEATURE_XSAVE};
use crate::cpu::interrupts::enable_irq;
use crate::cpu::lapic::{LvtTimerMode, LAPIC};
use crate::cpu::percpu::{this_cpu, PerCpuArch};
use crate::error::SvsmError;
use crate::mm::alloc::{allocate_pages, get_order};
use crate::types::PAGE_SIZE;
use crate::utils::zero_mem_region;
use core::any::Any;
use core::cell::OnceCell;
use core::mem::MaybeUninit;

struct TdpVp {
    vcpu: Vcpu,
    l2ctls: L2CtlsFlags,
    sirte: Sirte,
}

impl TdpVp {
    fn init(&mut self, vm_id: TdpVmId, apic_id: u32, is_bsp: bool) {
        self.vcpu.init(vm_id, apic_id, is_bsp);
        self.l2ctls = L2CtlsFlags::EnableSharedEPTP;
        tdvps_l2_ctls(vm_id, self.l2ctls).expect("Failed to set L2 controls");
        self.sirte.init(vm_id).expect("Failed to init SIRTE");
    }

    fn run(&mut self) {
        self.vcpu.run();
        unreachable!("TDX: should never retrun from vcpu run loop");
    }
}

#[derive(Debug)]
pub struct TdPerCpu {
    apic_id: u32,
    is_bsp: bool,
    tdpvps: [OnceCell<VirtAddr>; MAX_NUM_L2_VMS],
}
unsafe impl Send for TdPerCpu {}
unsafe impl Sync for TdPerCpu {}

impl PerCpuArch for TdPerCpu {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn setup_on_cpu(&self) -> Result<(), SvsmError> {
        // Setup TD environment on BSP only
        if self.is_bsp {
            init_tdps(self.apic_id).map_err(SvsmError::Tdx)?;
            register_interrupt_handlers()?;
        }

        if cpu_has_feature(X86_FEATURE_XSAVE) {
            write_cr4(read_cr4() | CR4Flags::OSXSAVE);
        }

        (*LAPIC).init();
        (*LAPIC).setup_lvt_timer(LvtTimerMode::TscDeadline, TIMER_VECTOR);
        enable_irq();

        Ok(())
    }
}

impl TdPerCpu {
    pub fn new(apic_id: u32, is_bsp: bool) -> Self {
        let tdpvps = {
            let mut tdpvps: [MaybeUninit<OnceCell<VirtAddr>>; MAX_NUM_L2_VMS] =
                unsafe { MaybeUninit::uninit().assume_init() };
            for tdpvp in tdpvps.iter_mut() {
                *tdpvp = MaybeUninit::new(OnceCell::new());
            }
            unsafe { core::mem::transmute::<_, [OnceCell<VirtAddr>; MAX_NUM_L2_VMS]>(tdpvps) }
        };
        Self {
            apic_id,
            is_bsp,
            tdpvps,
        }
    }

    #[allow(dead_code)]
    fn run_tdpvp(&self, vm_id: TdpVmId) {
        let vaddr = self.tdpvps[vm_id.index()].get_or_init(|| {
            let order = get_order(core::mem::size_of::<TdpVp>());
            let vaddr = allocate_pages(order).expect("Failed to allocate TdpVp");
            zero_mem_region(vaddr, vaddr + (1 << order) * PAGE_SIZE);
            vaddr
        });
        let tdpvp = unsafe { &mut *vaddr.as_mut_ptr::<TdpVp>().cast::<TdpVp>() };

        tdpvp.init(vm_id, self.apic_id, self.is_bsp);
        tdpvp.run();
    }
}

pub fn this_vcpu(vm_id: TdpVmId) -> &'static Vcpu {
    if let Some(td_percpu) = this_cpu().arch.as_any().downcast_ref::<TdPerCpu>() {
        if let Some(vaddr) = td_percpu.tdpvps[vm_id.index()].get() {
            if !vaddr.is_null() {
                let tdpvp = unsafe { &*vaddr.as_ptr::<TdpVp>().cast::<TdpVp>() };
                return &tdpvp.vcpu;
            }
        }
    }

    panic!("TDX: NO vcpu found for VM{:?}", vm_id)
}

pub fn this_vcpu_mut(vm_id: TdpVmId) -> &'static mut Vcpu {
    if let Some(td_percpu) = this_cpu().arch.as_any().downcast_ref::<TdPerCpu>() {
        if let Some(vaddr) = td_percpu.tdpvps[vm_id.index()].get() {
            if !vaddr.is_null() {
                let tdpvp = unsafe { &mut *vaddr.as_mut_ptr::<TdpVp>().cast::<TdpVp>() };
                return &mut tdpvp.vcpu;
            }
        }
    }

    panic!("TDX: NO vcpu found for VM{:?}", vm_id)
}

pub fn this_sirte_mut(vm_id: TdpVmId) -> &'static mut Sirte {
    if let Some(td_percpu) = this_cpu().arch.as_any().downcast_ref::<TdPerCpu>() {
        if let Some(vaddr) = td_percpu.tdpvps[vm_id.index()].get() {
            if !vaddr.is_null() {
                let tdpvp = unsafe { &mut *vaddr.as_mut_ptr::<TdpVp>().cast::<TdpVp>() };
                return &mut tdpvp.sirte;
            }
        }
    }

    panic!("TDX: NO sirte found for VM{:?}", vm_id)
}
