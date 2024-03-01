// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 Intel Corporation
//
// Author:
//      Chuanxiao Dong <chuanxiao.dong@intel.com>
//      Jason CJ Chen <jason.cj.chen@intel.com>

use super::error::TdxError;
use super::utils::{td_num_l2_vms, TdpVmId, FIRST_VM_ID, MAX_NUM_L2_VMS};
use super::vcpuid::Vcpuid;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use core::cell::OnceCell;
use core::mem::MaybeUninit;

#[allow(dead_code)]
#[derive(Debug)]
pub struct Tdp {
    vm_id: TdpVmId,
    bsp_apic_id: u32,
    vcpuid: Vcpuid,
}

type Tdps = [OnceCell<Tdp>; MAX_NUM_L2_VMS];
static TDPS: ImmutAfterInitCell<Tdps> = ImmutAfterInitCell::uninit();
static NUM_L2_VMS: ImmutAfterInitCell<u64> = ImmutAfterInitCell::new(0);

impl Tdp {
    fn new(vm_id: TdpVmId, apic_id: u32) -> Self {
        Self {
            vm_id,
            bsp_apic_id: apic_id,
            vcpuid: Vcpuid::new(),
        }
    }

    fn init(&mut self) -> Result<(), TdxError> {
        self.vcpuid.init();
        Ok(())
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

    Ok(())
}
