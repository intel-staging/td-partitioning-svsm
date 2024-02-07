// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Peter Fang <peter.fang@intel.com>

extern crate alloc;

use super::error::TdxError;
use super::utils::TdpVmId;
use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;

trait MsrEmulation: core::fmt::Debug {
    fn address(&self) -> u32;

    fn read(&self, vm_id: TdpVmId) -> Result<u64, TdxError> {
        log::warn!("VM{:?}: Unsupported RDMSR: 0x{:x}", vm_id, self.address());
        Err(TdxError::Vmsr)
    }

    fn write(&mut self, vm_id: TdpVmId, _data: u64) -> Result<(), TdxError> {
        log::warn!("VM{:?}: Unsupported WRMSR: 0x{:x}", vm_id, self.address());
        Err(TdxError::Vmsr)
    }
}

trait BoxedMsrEmulation: Sized + MsrEmulation {
    fn new(msr: u32) -> Self;

    fn alloc<'a>(msr: u32) -> Box<dyn MsrEmulation + 'a>
    where
        Self: 'a,
    {
        Box::new(Self::new(msr))
    }
}

#[derive(Debug)]
struct UnsupportedMsr(u32);

impl BoxedMsrEmulation for UnsupportedMsr {
    fn new(msr: u32) -> Self {
        UnsupportedMsr(msr)
    }
}

impl MsrEmulation for UnsupportedMsr {
    fn address(&self) -> u32 {
        self.0
    }
}

struct GuestCpuMsr(Box<dyn MsrEmulation>);

pub struct GuestCpuMsrs {
    vm_id: TdpVmId,
    msrs: BTreeMap<u32, GuestCpuMsr>,
}

#[allow(dead_code)]
impl GuestCpuMsrs {
    pub fn init(&mut self, vm_id: TdpVmId) {
        self.vm_id = vm_id;
        self.msrs = BTreeMap::new();
    }

    fn get(&self, index: u32) -> Option<&dyn MsrEmulation> {
        self.msrs.get(&index).map(|m| &*m.0)
    }

    fn get_mut(&mut self, index: u32) -> Option<&mut Box<dyn MsrEmulation>> {
        self.msrs.get_mut(&index).map(|m| &mut m.0)
    }

    fn set(&mut self, index: u32, msr: Box<dyn MsrEmulation>) {
        let _ = self.msrs.insert(index, GuestCpuMsr(msr));
    }

    pub fn read(&self, msr: u32) -> Result<u64, TdxError> {
        if let Some(m) = self.get(msr) {
            m.read(self.vm_id)
        } else {
            UnsupportedMsr::new(msr).read(self.vm_id)
        }
    }

    pub fn write(&mut self, msr: u32, data: u64) -> Result<(), TdxError> {
        let vm_id = self.vm_id;
        if let Some(m) = self.get_mut(msr) {
            m.write(vm_id, data)
        } else {
            UnsupportedMsr::new(msr).write(vm_id, data)
        }
    }
}
