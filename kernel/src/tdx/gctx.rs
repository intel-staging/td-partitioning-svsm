// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

use super::percpu::this_vcpu;
use super::utils::TdpVmId;
use super::vmcs::Vmcs;
use super::vmcs_lib::VmcsField64Guest;
use crate::address::VirtAddr;
use crate::locking::SpinLock;
use crate::mm::address_space::virt_to_phys;
use core::default::Default;
use core::fmt::Debug;

#[derive(Debug)]
struct Cache<T>
where
    T: Copy + Clone + Debug + Default,
{
    val: T,
    dirty: bool,
}

pub struct RegCache<T>
where
    T: Copy + Clone + Debug + Default,
{
    vm_id: TdpVmId,
    cache: SpinLock<Option<Cache<T>>>,
    readhw: Option<fn(&Vmcs) -> T>,
    writehw: Option<fn(&Vmcs, T)>,
}

#[allow(dead_code)]
impl<T: Copy + Clone + Debug + Default> RegCache<T> {
    pub fn new(
        vm_id: TdpVmId,
        readhw: Option<fn(&Vmcs) -> T>,
        writehw: Option<fn(&Vmcs, T)>,
    ) -> Self {
        RegCache {
            vm_id,
            cache: SpinLock::new(None),
            readhw,
            writehw,
        }
    }

    pub fn vm_id(&self) -> TdpVmId {
        self.vm_id
    }

    // read from hardware if cache doesn't exists, and
    // cache the value to accelorate reading for the next time.
    pub fn read_cache(&self) -> T {
        let mut cache = self.cache.lock();
        if let Some(v) = cache.as_ref() {
            return v.val;
        }

        let v = if let Some(readhw) = self.readhw {
            let vmcs = this_vcpu(self.vm_id).get_vmcs();
            readhw(vmcs)
        } else {
            T::default()
        };
        *cache = Some(Cache {
            val: v,
            dirty: false,
        });
        v
    }

    // write the value to cache
    pub fn write_cache(&mut self, val: T) {
        *self.cache.lock() = Some(Cache { val, dirty: true });
    }

    fn take_cache(&mut self) -> Option<Cache<T>> {
        let mut cache = self.cache.lock();
        cache.take()
    }

    // write_hw should be called if the write is done
    // by write_cache as write_cache won't write the value
    // to hardware but just cache it.
    pub fn sync_cache(&mut self) {
        if let Some(writehw) = self.writehw {
            let vmcs = this_vcpu(self.vm_id).get_vmcs();
            if self.readhw.is_none() {
                // If there is no readhw operation, which means this
                // is used for a preserved register. Keep the cache.
                if let Some(c) = self.cache.lock().as_ref() {
                    if c.dirty {
                        writehw(vmcs, c.val);
                    }
                }
            } else if let Some(c) = self.take_cache() {
                if c.dirty {
                    writehw(vmcs, c.val);
                }
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Copy, Clone, Default)]
struct GuestCpuGPRegs {
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

#[repr(C)]
#[repr(align(256))]
#[derive(Clone, Copy, Default)]
struct GuestCpuTdpContext {
    gpregs: GuestCpuGPRegs,
    rflags: u64,
    rip: u64,
    ssp: u64,
    intr_status: u16,
}

const REAL_MODE_RIP: u64 = 0xfff0;
const REAL_MODE_RFLAGS: u64 = 0x02;

pub struct GuestCpuContext {
    vm_id: TdpVmId,
    tdp_ctx: GuestCpuTdpContext,
    tdp_ctx_pa: u64,
    ia32_efer: RegCache<u64>,
}

impl GuestCpuContext {
    pub fn init(&mut self, vm_id: TdpVmId) {
        self.vm_id = vm_id;
        self.tdp_ctx_pa = u64::from(virt_to_phys(VirtAddr::from(core::ptr::addr_of!(
            self.tdp_ctx
        ))));
        // IA32_EFER is preserved across L2 VM exit & entry, so the
        // cache in RegCache is always up to date. So no need to provide
        // a readhw operation.
        self.ia32_efer = RegCache::new(
            vm_id,
            None,
            Some(|vmcs, v| vmcs.write64(VmcsField64Guest::IA32_EFER, v)),
        );
    }

    pub fn reset(&mut self) {
        self.tdp_ctx = GuestCpuTdpContext::default();
        self.tdp_ctx.rip = REAL_MODE_RIP;
        self.tdp_ctx.rflags = REAL_MODE_RFLAGS;
        self.ia32_efer.write_cache(0);
    }
}
