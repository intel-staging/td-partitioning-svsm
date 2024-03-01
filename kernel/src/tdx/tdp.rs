// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 Intel Corporation
//
// Author:
//      Chuanxiao Dong <chuanxiao.dong@intel.com>
//      Jason CJ Chen <jason.cj.chen@intel.com>

extern crate alloc;

use super::error::TdxError;
use super::utils::{td_num_l2_vms, TdpVmId, FIRST_VM_ID, MAX_NUM_L2_VMS};
use super::vcpu::kick_vcpu;
use super::vcpu_comm::VcpuCommBlock;
use super::vcpuid::Vcpuid;
use crate::cpu::smp::get_nr_cpus;
use crate::locking::RWLock;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use core::cell::OnceCell;
use core::mem::MaybeUninit;

#[derive(Debug)]
pub struct Tdp {
    vm_id: TdpVmId,
    bsp_apic_id: u32,
    vcpuid: Vcpuid,
    vcpu_comms: RWLock<BTreeMap<u32, Arc<VcpuCommBlock>>>,
}

type Tdps = [OnceCell<Tdp>; MAX_NUM_L2_VMS];
static TDPS: ImmutAfterInitCell<Tdps> = ImmutAfterInitCell::uninit();
static NUM_L2_VMS: ImmutAfterInitCell<u64> = ImmutAfterInitCell::new(0);

type TdpCb = Arc<BTreeMap<u32, Arc<VcpuCommBlock>>>;
type TdpCbs = [OnceCell<TdpCb>; MAX_NUM_L2_VMS];
static TDPCBS: ImmutAfterInitCell<TdpCbs> = ImmutAfterInitCell::uninit();

impl Tdp {
    fn new(vm_id: TdpVmId, apic_id: u32) -> Self {
        Self {
            vm_id,
            bsp_apic_id: apic_id,
            vcpuid: Vcpuid::new(),
            vcpu_comms: RWLock::new(BTreeMap::new()),
        }
    }

    fn init(&mut self) -> Result<(), TdxError> {
        self.vcpuid.init();
        Ok(())
    }

    pub fn register_vcpu_cb(&self, cb: Arc<VcpuCommBlock>) {
        let apic_id = cb.apic_id;
        let mut vcpu_comms = self.vcpu_comms.lock_write();
        vcpu_comms.insert(apic_id, cb);
        if vcpu_comms.len() as u64 == get_nr_cpus() {
            TDPCBS[self.vm_id.index()]
                .set(Arc::new(vcpu_comms.clone()))
                .expect("Failed to init TDPCBS");
        }

        if apic_id != self.bsp_apic_id {
            // BSP may be waiting for all AP vcpus to complete
            // the VcpuCommBlock registration. Kick BSP in case
            // it is waiting.
            kick_vcpu(self.bsp_apic_id);
        }
    }

    pub fn vcpu_cbs_ready(&self) -> bool {
        self.vcpu_comms.lock_write().len() as u64 == get_nr_cpus()
    }
}

pub fn init_tdps(apic_id: u32) -> Result<(), TdxError> {
    let tdps = {
        let mut tdps: [MaybeUninit<OnceCell<Tdp>>; MAX_NUM_L2_VMS] =
            unsafe { MaybeUninit::uninit().assume_init() };
        for tdp in tdps.iter_mut() {
            *tdp = MaybeUninit::new(OnceCell::new());
        }
        unsafe { core::mem::transmute::<_, Tdps>(tdps) }
    };

    TDPS.init(&tdps).map_err(|_| TdxError::TdpNotSupport)?;

    NUM_L2_VMS.reinit(&td_num_l2_vms()?);
    for (i, tdp) in TDPS.iter().enumerate() {
        if (0..*NUM_L2_VMS as usize).contains(&i) {
            let vm_id = TdpVmId::new(FIRST_VM_ID + i as u64)?;
            let mut data = Tdp::new(vm_id, apic_id);
            data.init()?;
            tdp.set(data).map_err(|_| TdxError::TdpNotSupport)?;
        }
    }

    let tdpcbs = {
        let mut tdpcbs: [MaybeUninit<OnceCell<TdpCb>>; MAX_NUM_L2_VMS] =
            unsafe { MaybeUninit::uninit().assume_init() };
        for tdpcb in tdpcbs.iter_mut() {
            *tdpcb = MaybeUninit::new(OnceCell::new());
        }
        unsafe { core::mem::transmute::<_, TdpCbs>(tdpcbs) }
    };

    TDPCBS.init(&tdpcbs).map_err(|_| TdxError::TdpNotSupport)?;

    Ok(())
}

pub fn this_tdp(vm_id: TdpVmId) -> &'static Tdp {
    assert!((0..*NUM_L2_VMS as usize).contains(&vm_id.index()));
    TDPS[vm_id.index()].get().unwrap()
}

#[allow(dead_code)]
pub fn get_vcpu_cb(vm_id: TdpVmId, apic_id: u32) -> Option<Arc<VcpuCommBlock>> {
    TDPCBS[vm_id.index()]
        .get()
        .and_then(|cbs| cbs.get(&apic_id).cloned())
}
