// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Peter Fang <peter.fang@intel.com>

extern crate alloc;

use super::error::TdxError;
use super::msr_bitmap::{InterceptMsrType, MsrBitmap, MsrBitmapRef};
use super::percpu::this_vcpu;
use super::tdcall::{tdvmcall_rdmsr, tdvmcall_wrmsr, TdVmcallError};
use super::utils::TdpVmId;
use super::vmcs_lib::VmcsField64Guest;
use crate::cpu::control_regs::CR0Flags;
use crate::cpu::msr::*;
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

#[derive(Debug)]
struct PassthruMsr(u32);

impl BoxedMsrEmulation for PassthruMsr {
    fn new(msr: u32) -> Self {
        PassthruMsr(msr)
    }
}

impl MsrEmulation for PassthruMsr {
    fn address(&self) -> u32 {
        self.0
    }

    fn read(&self, _vm_id: TdpVmId) -> Result<u64, TdxError> {
        tdvmcall_rdmsr(self.address()).map_err(|e| {
            if e != TdVmcallError::VmcallOperandInvalid {
                panic!("Fatal RDMSR 0x{:x}: error {:?}", self.address(), e);
            }
            log::warn!("Illegal RDMSR 0x{:x}: error {:?}", self.address(), e);
            TdxError::Vmsr
        })
    }

    fn write(&mut self, _vm_id: TdpVmId, data: u64) -> Result<(), TdxError> {
        tdvmcall_wrmsr(self.address(), data).map_err(|e| {
            if e != TdVmcallError::VmcallOperandInvalid {
                panic!("Fatal WRMSR 0x{:x}: error {:?}", self.address(), e);
            }
            log::warn!("Illegal WRMSR 0x{:x}: error {:?}", self.address(), e);
            TdxError::Vmsr
        })
    }
}

#[derive(Debug)]
struct PatVmsr(u64);

impl BoxedMsrEmulation for PatVmsr {
    fn new(_msr: u32) -> Self {
        PatVmsr(PAT_POWER_ON_VALUE)
    }
}

impl MsrEmulation for PatVmsr {
    fn address(&self) -> u32 {
        MSR_IA32_PAT
    }

    fn read(&self, _vm_id: TdpVmId) -> Result<u64, TdxError> {
        Ok(self.0)
    }

    fn write(&mut self, vm_id: TdpVmId, data: u64) -> Result<(), TdxError> {
        for (i, pat) in data.to_le_bytes().into_iter().enumerate() {
            // Check for invalid values
            if pat & 0xf8 != 0 || (pat & 0x6) == 0x2 {
                log::info!("PAT: invalid PA{} value 0x{:x}", i, pat);
                return Err(TdxError::Vmsr);
            }
        }
        // If context->cr0.CD is set, we defer any further requests to
        // write the guest's IA32_PAT until the time when the guest's
        // CR0.CD is being cleared
        if this_vcpu(vm_id).get_ctx().get_cr0() & CR0Flags::CD.bits() == 0 {
            this_vcpu(vm_id)
                .get_vmcs()
                .write64(VmcsField64Guest::IA32_PAT, data);
        }
        self.0 = data;
        Ok(())
    }
}

const PASSTHROUGH_MSRS: &[u32] = &[
    MSR_IA32_SPEC_CTRL,
    MSR_IA32_PRED_CMD,
    MSR_IA32_BIOS_SIGN_ID,
    MSR_IA32_UMWAIT_CONTROL,
    MSR_IA32_ARCH_CAPABILITIES,
    MSR_IA32_SYSENTER_CS,
    MSR_IA32_SYSENTER_ESP,
    MSR_IA32_SYSENTER_EIP,
    MSR_IA32_XFD,
    MSR_IA32_DEBUGCTL,
    MSR_IA32_XSS,
    MSR_IA32_STAR,
    MSR_IA32_LSTAR,
    MSR_IA32_FMASK,
    MSR_IA32_FS_BASE,
    MSR_IA32_GS_BASE,
    MSR_IA32_KERNEL_GS_BASE,
    MSR_IA32_TSC_AUX,
];

type EmulatedMsrs = (u32, fn(u32) -> Box<dyn MsrEmulation>);
const EMULATED_MSRS: &[EmulatedMsrs] = &[(MSR_IA32_PAT, PatVmsr::alloc)];

struct GuestCpuMsr(Box<dyn MsrEmulation>);

pub struct GuestCpuMsrs {
    vm_id: TdpVmId,
    msrs: BTreeMap<u32, GuestCpuMsr>,
    bitmap: MsrBitmap,
}

#[allow(dead_code)]
impl GuestCpuMsrs {
    pub fn init(&mut self, vm_id: TdpVmId) {
        self.vm_id = vm_id;
        self.msrs = BTreeMap::new();
        self.bitmap = MsrBitmap::new();
    }

    pub fn reset(&mut self) {
        for &(msr, allocfn) in EMULATED_MSRS {
            self.set(msr, allocfn(msr));
        }

        for &msr in PASSTHROUGH_MSRS.iter() {
            self.set(msr, PassthruMsr::alloc(msr));
        }

        let mut bitmap = self.new_bitmap_ref();

        for &msr in PASSTHROUGH_MSRS.iter() {
            bitmap
                .intercept(msr, InterceptMsrType::Disable)
                .unwrap_or_else(|_| {
                    panic!(
                        "error configuring MSR interception for passthru MSR 0x{:x}",
                        msr
                    )
                });
        }

        // CR0.CD is initially clear
        bitmap
            .intercept(MSR_IA32_PAT, InterceptMsrType::Disable)
            .expect("error configuring MSR interception for PAT MSR");

        // Unsupported MSRs are intercepted by default
    }

    fn new_bitmap_ref(&mut self) -> MsrBitmapRef<'_> {
        MsrBitmapRef::new(self.vm_id, &mut self.bitmap)
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
