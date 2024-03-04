// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Peter Fang <peter.fang@intel.com>

extern crate alloc;

use super::error::TdxError;
use super::msr_bitmap::{InterceptMsrType, MsrBitmap, MsrBitmapRef};
use super::percpu::{this_vcpu, this_vcpu_mut};
use super::tdcall::{tdvmcall_rdmsr, tdvmcall_wrmsr, TdVmcallError};
use super::utils::TdpVmId;
use super::vmcs_lib::{VmcsField64Control, VmcsField64Guest};
use crate::cpu::control_regs::CR0Flags;
use crate::cpu::cpuid::cpuid;
use crate::cpu::efer::EFERFlags;
use crate::cpu::msr::*;
use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;
use core::ops::RangeInclusive;

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
struct ZeroedRoMsr(u32);

impl BoxedMsrEmulation for ZeroedRoMsr {
    fn new(msr: u32) -> Self {
        ZeroedRoMsr(msr)
    }
}

impl MsrEmulation for ZeroedRoMsr {
    fn address(&self) -> u32 {
        self.0
    }

    fn read(&self, _vm_id: TdpVmId) -> Result<u64, TdxError> {
        Ok(0)
    }
}

#[derive(Debug)]
struct IgnoredWoMsr(u32);

impl BoxedMsrEmulation for IgnoredWoMsr {
    fn new(msr: u32) -> Self {
        IgnoredWoMsr(msr)
    }
}

impl MsrEmulation for IgnoredWoMsr {
    fn address(&self) -> u32 {
        self.0
    }

    fn write(&mut self, _vm_id: TdpVmId, _data: u64) -> Result<(), TdxError> {
        Ok(())
    }
}

#[derive(Debug)]
struct IgnoredRwMsr(u32);

impl BoxedMsrEmulation for IgnoredRwMsr {
    fn new(msr: u32) -> Self {
        IgnoredRwMsr(msr)
    }
}

impl MsrEmulation for IgnoredRwMsr {
    fn address(&self) -> u32 {
        self.0
    }

    fn read(&self, _vm_id: TdpVmId) -> Result<u64, TdxError> {
        Ok(0)
    }

    fn write(&mut self, _vm_id: TdpVmId, _data: u64) -> Result<(), TdxError> {
        Ok(())
    }
}

#[derive(Debug)]
struct NoopMsr(u32, u64); // (msr, data)

impl BoxedMsrEmulation for NoopMsr {
    fn new(msr: u32) -> Self {
        NoopMsr(msr, 0)
    }
}

impl MsrEmulation for NoopMsr {
    fn address(&self) -> u32 {
        self.0
    }

    fn read(&self, _vm_id: TdpVmId) -> Result<u64, TdxError> {
        Ok(self.1)
    }

    fn write(&mut self, _vm_id: TdpVmId, data: u64) -> Result<(), TdxError> {
        self.1 = data;
        Ok(())
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

#[derive(Debug)]
struct EferVmsr;

impl BoxedMsrEmulation for EferVmsr {
    fn new(_msr: u32) -> Self {
        EferVmsr
    }
}

impl MsrEmulation for EferVmsr {
    fn address(&self) -> u32 {
        EFER
    }

    fn read(&self, vm_id: TdpVmId) -> Result<u64, TdxError> {
        Ok(this_vcpu(vm_id).get_ctx().get_efer())
    }

    fn write(&mut self, vm_id: TdpVmId, data: u64) -> Result<(), TdxError> {
        this_vcpu_mut(vm_id).get_ctx_mut().set_efer(data);
        Ok(())
    }
}

#[derive(Debug)]
struct FeatureControlVmsr(u64);

impl BoxedMsrEmulation for FeatureControlVmsr {
    fn new(_msr: u32) -> Self {
        // Lock out all of the features
        FeatureControlVmsr(MsrIa32FeatureControl::LOCK.bits())
    }
}

impl MsrEmulation for FeatureControlVmsr {
    fn address(&self) -> u32 {
        MSR_IA32_FEATURE_CONTROL
    }

    fn read(&self, _vm_id: TdpVmId) -> Result<u64, TdxError> {
        Ok(self.0)
    }
}

#[derive(Debug)]
struct McgStatusVmsr;

impl BoxedMsrEmulation for McgStatusVmsr {
    fn new(_msr: u32) -> Self {
        McgStatusVmsr
    }
}

impl MsrEmulation for McgStatusVmsr {
    fn address(&self) -> u32 {
        MSR_IA32_MCG_STATUS
    }

    fn read(&self, _vm_id: TdpVmId) -> Result<u64, TdxError> {
        Ok(0)
    }

    fn write(&mut self, _vm_id: TdpVmId, data: u64) -> Result<(), TdxError> {
        if data == 0 {
            Ok(())
        } else {
            log::info!("Unsupported MCG_STATUS val: 0x{:x}", data);
            Err(TdxError::Vmsr)
        }
    }
}

#[derive(Debug)]
struct PerfStatusVmsr;

impl BoxedMsrEmulation for PerfStatusVmsr {
    fn new(_msr: u32) -> Self {
        PerfStatusVmsr
    }
}

impl MsrEmulation for PerfStatusVmsr {
    fn address(&self) -> u32 {
        MSR_IA32_PERF_STATUS
    }

    // Use the base frequency state of pCPU as the emulated reg field:
    //   - IA32_PERF_STATUS[15:0] Current performance State Value
    //
    // Assuming (base frequency ratio << 8) is a valid state value for
    // all CPU models
    fn read(&self, _vm_id: TdpVmId) -> Result<u64, TdxError> {
        // CPUID.16H:eax[15:0] Base CPU Frequency (MHz)
        // CPUID.16H:ecx[15:0] Bus Frequency (MHz)
        // ratio = CPU_frequency/bus_frequency
        let cpuid16h = cpuid(0x16).unwrap();
        let data = ((cpuid16h.eax / cpuid16h.ecx) & 0xffu32) << 8;
        Ok(data.into())
    }
}

#[derive(Debug)]
struct MiscEnableVmsr(MsrIa32MiscEnable);

impl BoxedMsrEmulation for MiscEnableVmsr {
    fn new(_msr: u32) -> Self {
        let mut misc = MsrIa32MiscEnable::from_bits_retain(read_msr(MSR_IA32_MISC_ENABLE).unwrap());
        misc.remove(MsrIa32MiscEnable::EN_EIST);
        // MONITOR/MWAIT cause #VE unconditionally
        misc.remove(MsrIa32MiscEnable::EN_MONITOR);
        misc.remove(MsrIa32MiscEnable::XD_DISABLE);
        MiscEnableVmsr(misc)
    }
}

impl MsrEmulation for MiscEnableVmsr {
    fn address(&self) -> u32 {
        MSR_IA32_MISC_ENABLE
    }

    fn read(&self, _vm_id: TdpVmId) -> Result<u64, TdxError> {
        Ok(self.0.bits())
    }

    fn write(&mut self, vm_id: TdpVmId, data: u64) -> Result<(), TdxError> {
        let mut misc = MsrIa32MiscEnable::from_bits_retain(data);

        if misc.contains(MsrIa32MiscEnable::EN_MONITOR) {
            return Err(TdxError::Vmsr);
        }
        // According to Intel SDM Vol 4 2.1 & Vol 3A 4.1.4,
        // EFER.NXE should be cleared if guest disables XD in IA32_MISC_ENABLE
        if misc.contains(MsrIa32MiscEnable::XD_DISABLE)
            && !self.0.contains(MsrIa32MiscEnable::XD_DISABLE)
        {
            let mut efer = EFERFlags::from_bits_retain(this_vcpu(vm_id).get_ctx().get_efer());
            efer.remove(EFERFlags::NXE);
            this_vcpu_mut(vm_id).get_ctx_mut().set_efer(efer.bits());
        }
        misc.remove(MsrIa32MiscEnable::EN_EIST);
        self.0 = misc;
        Ok(())
    }
}

#[derive(Debug)]
struct TscVmsr;

impl BoxedMsrEmulation for TscVmsr {
    fn new(_msr: u32) -> Self {
        TscVmsr
    }
}

impl MsrEmulation for TscVmsr {
    fn address(&self) -> u32 {
        MSR_IA32_TIME_STAMP_COUNTER
    }

    // Intel SDM Vol 3 17.17.3:
    //
    // If an execution of WRMSR to the IA32_TIME_STAMP_COUNTER MSR adds
    // (or subtracts) value X from the TSC, the logical processor also
    // adds (or subtracts) value X from the IA32_TSC_ADJUST MSR.
    //
    // So, here we should update VMCS.OFFSET and vAdjust accordingly.
    //   - VMCS.OFFSET = L2 TSC - L1 TSC
    //   - vAdjust += VMCS.OFFSET's delta
    fn write(&mut self, vm_id: TdpVmId, data: u64) -> Result<(), TdxError> {
        // Intel SDM Vol 3 24.6.5
        // The value of the TSC offset is added to the value of the
        // time-stamp counter
        let delta = data
            - (this_vcpu(vm_id)
                .get_vmcs()
                .read64(VmcsField64Control::TSC_OFFSET)
                + rdtsc());
        let vmsrs = this_vcpu_mut(vm_id).get_ctx_mut().get_msrs_mut();
        let adj = vmsrs.read(MSR_IA32_TSC_ADJUST).unwrap();
        vmsrs.write(MSR_IA32_TSC_ADJUST, adj + delta)
    }
}

#[derive(Debug)]
struct TscAdjustVmsr(u64);

impl TscAdjustVmsr {
    // If TSC_OFFSET is 0, no need to trap the writes to IA32_TSC_DEADLINE
    // since L2 TSC == L1 TSC. Only writes to vTSC_ADJUST are trapped.
    fn update_tsc_msr_bitmap(vm_id: TdpVmId, intercept: bool) {
        let mut bitmap = this_vcpu_mut(vm_id)
            .get_ctx_mut()
            .get_msrs_mut()
            .new_bitmap_ref();

        if intercept {
            bitmap
                .intercept(MSR_IA32_TSC_DEADLINE, InterceptMsrType::ReadWrite)
                .expect("error configuring MSR interception for TSCDEADLINE MSR");
            bitmap
                .intercept(MSR_IA32_TSC_ADJUST, InterceptMsrType::ReadWrite)
                .expect("error configuring MSR interception for TSCADJ MSR");

            if bitmap.is_dirty() {
                // Update vTSC_DEADLINE
                this_vcpu_mut(vm_id)
                    .get_ctx_mut()
                    .get_msrs_mut()
                    .write(
                        MSR_IA32_TSC_DEADLINE,
                        read_msr(MSR_IA32_TSC_DEADLINE).unwrap(),
                    )
                    .unwrap();
            }
        } else {
            bitmap
                .intercept(MSR_IA32_TSC_DEADLINE, InterceptMsrType::Disable)
                .expect("error configuring MSR interception for TSCDEADLINE MSR");
            bitmap
                .intercept(MSR_IA32_TSC_ADJUST, InterceptMsrType::Write)
                .expect("error configuring MSR interception for TSCADJ MSR");

            if bitmap.is_dirty() {
                let vmsrs = this_vcpu_mut(vm_id).get_ctx_mut().get_msrs_mut();
                if read_msr(MSR_IA32_TSC_DEADLINE).unwrap() != 0 {
                    // If the timer hasn't expired, update TSC_DEADLINE
                    write_msr(
                        MSR_IA32_TSC_DEADLINE,
                        vmsrs.read(MSR_IA32_TSC_DEADLINE).unwrap(),
                    )
                    .unwrap();
                } else {
                    // If the timer has expired, write 0 to vTSC_DEADLINE
                    vmsrs.write(MSR_IA32_TSC_DEADLINE, 0).unwrap();
                }
            }
        }
    }
}

impl BoxedMsrEmulation for TscAdjustVmsr {
    fn new(_msr: u32) -> Self {
        // Intel SDM Vol 3 17.17.3
        // Reset value is 0
        TscAdjustVmsr(0)
    }
}

impl MsrEmulation for TscAdjustVmsr {
    fn address(&self) -> u32 {
        MSR_IA32_TSC_ADJUST
    }

    fn read(&self, _vm_id: TdpVmId) -> Result<u64, TdxError> {
        Ok(self.0)
    }

    // Intel SDM Vol 3 17.17.3:
    //
    // If an execution of WRMSR to the IA32_TSC_ADJUST MSR adds (or
    // subtracts) value X from that MSR, the logical processor also
    // adds (or subtracts) value X from the TSC.
    //
    // So, here we should update VMCS.OFFSET and vAdjust accordingly.
    //   - VMCS.OFFSET += vAdjust's delta
    //   - vAdjust = new vAdjust set by the guest
    fn write(&mut self, vm_id: TdpVmId, data: u64) -> Result<(), TdxError> {
        // Delta between the new and the existing IA32_TSC_ADJUST
        let vmcs = this_vcpu(vm_id).get_vmcs();
        let delta = data - self.0;
        let offset = vmcs.read64(VmcsField64Control::TSC_OFFSET);
        if delta != 0 {
            // Apply this delta to the existing TSC_OFFSET
            vmcs.write64(VmcsField64Control::TSC_OFFSET, offset + delta);
        }
        // Update this MSR
        self.0 = data;
        Self::update_tsc_msr_bitmap(vm_id, offset + delta != 0);
        Ok(())
    }
}

#[derive(Debug)]
struct TscDeadlineVmsr(u64);

impl TscDeadlineVmsr {
    fn get(&self) -> u64 {
        self.0
    }

    fn set(&mut self, val: u64) {
        self.0 = val;
    }
}

impl BoxedMsrEmulation for TscDeadlineVmsr {
    fn new(_msr: u32) -> Self {
        // Intel SDM Vol 3 10.5.4.1
        // Reset value is 0
        TscDeadlineVmsr(0)
    }
}

impl MsrEmulation for TscDeadlineVmsr {
    fn address(&self) -> u32 {
        MSR_IA32_TSC_DEADLINE
    }

    fn read(&self, vm_id: TdpVmId) -> Result<u64, TdxError> {
        let get_dlt = || self.get();
        Ok(this_vcpu(vm_id).get_vlapic().get_tsc_deadline_msr(get_dlt))
    }

    fn write(&mut self, vm_id: TdpVmId, data: u64) -> Result<(), TdxError> {
        let set_dlt = |d| self.set(d);
        this_vcpu_mut(vm_id)
            .get_vlapic_mut()
            .set_tsc_deadline_msr(data, set_dlt);
        Ok(())
    }
}

#[derive(Debug)]
struct ApicBaseVmsr;

impl BoxedMsrEmulation for ApicBaseVmsr {
    fn new(_msr: u32) -> Self {
        ApicBaseVmsr
    }
}

impl MsrEmulation for ApicBaseVmsr {
    fn address(&self) -> u32 {
        MSR_IA32_APIC_BASE
    }

    fn read(&self, vm_id: TdpVmId) -> Result<u64, TdxError> {
        Ok(this_vcpu(vm_id).get_vlapic().get_apicbase())
    }

    fn write(&mut self, vm_id: TdpVmId, data: u64) -> Result<(), TdxError> {
        this_vcpu_mut(vm_id).get_vlapic_mut().set_apicbase(data)
    }
}

#[derive(Debug)]
struct X2ApicVmsr(u32);

impl BoxedMsrEmulation for X2ApicVmsr {
    fn new(msr: u32) -> Self {
        X2ApicVmsr(msr)
    }
}

impl MsrEmulation for X2ApicVmsr {
    fn address(&self) -> u32 {
        self.0
    }

    fn read(&self, vm_id: TdpVmId) -> Result<u64, TdxError> {
        this_vcpu(vm_id)
            .get_vlapic()
            .read_reg(self.address())
            .map(|d| d.into())
    }

    fn write(&mut self, vm_id: TdpVmId, data: u64) -> Result<(), TdxError> {
        this_vcpu_mut(vm_id)
            .get_vlapic_mut()
            .write_reg(self.address(), data)
    }
}

const PASSTHROUGH_MSRS: &[u32] = &[
    MSR_IA32_SPEC_CTRL,
    MSR_IA32_PRED_CMD,
    MSR_IA32_BIOS_SIGN_ID,
    MSR_IA32_UMWAIT_CONTROL,
    MSR_IA32_MTRR_CAP,
    MSR_IA32_ARCH_CAPABILITIES,
    MSR_IA32_SYSENTER_CS,
    MSR_IA32_SYSENTER_ESP,
    MSR_IA32_SYSENTER_EIP,
    MSR_IA32_XFD,
    MSR_IA32_DEBUGCTL,
    MSR_IA32_MTRR_DEF_TYPE,
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
const EMULATED_MSRS: &[EmulatedMsrs] = &[
    (MSR_IA32_TIME_STAMP_COUNTER, TscVmsr::alloc),
    (MSR_IA32_PLATFORM_ID, ZeroedRoMsr::alloc),
    (MSR_IA32_APIC_BASE, ApicBaseVmsr::alloc),
    (MSR_SMI_COUNT, ZeroedRoMsr::alloc),
    (MSR_IA32_FEATURE_CONTROL, FeatureControlVmsr::alloc),
    (MSR_IA32_TSC_ADJUST, TscAdjustVmsr::alloc),
    (MSR_IA32_BIOS_UPDT_TRIG, IgnoredWoMsr::alloc),
    (MSR_PLATFORM_INFO, ZeroedRoMsr::alloc),
    (MSR_MISC_FEATURE_ENABLES, ZeroedRoMsr::alloc),
    (MSR_IA32_MCG_CAP, ZeroedRoMsr::alloc),
    (MSR_IA32_MCG_STATUS, McgStatusVmsr::alloc),
    (MSR_IA32_PERF_STATUS, PerfStatusVmsr::alloc),
    (MSR_IA32_PERF_CTL, NoopMsr::alloc),
    (MSR_IA32_MISC_ENABLE, MiscEnableVmsr::alloc),
    (MSR_IA32_PAT, PatVmsr::alloc),
    (MSR_IA32_TSC_DEADLINE, TscDeadlineVmsr::alloc),
    (EFER, EferVmsr::alloc),
    (MSR_IA32_CSTAR, IgnoredRwMsr::alloc),
];

const MSR_RANGE_MTRR_RANGE: RangeInclusive<u32> =
    MSR_IA32_MTRR_RANGE_FIRST..=MSR_IA32_MTRR_RANGE_LAST;
const MSR_RANGE_X2APIC: RangeInclusive<u32> = MSR_IA32_EXT_APIC_FIRST..=MSR_IA32_EXT_APIC_LAST;

type EmulatedMsrsRange<'a> = (&'a RangeInclusive<u32>, fn(u32) -> Box<dyn MsrEmulation>);
const EMULATED_MSRS_RANGE: &[EmulatedMsrsRange<'_>] = &[
    (&MSR_RANGE_MTRR_RANGE, PassthruMsr::alloc),
    (&MSR_RANGE_X2APIC, X2ApicVmsr::alloc),
];

struct GuestCpuMsr(Box<dyn MsrEmulation>);

pub struct GuestCpuMsrs {
    vm_id: TdpVmId,
    msrs: BTreeMap<u32, GuestCpuMsr>,
    bitmap: MsrBitmap,
}

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

        for &(msrs, allocfn) in EMULATED_MSRS_RANGE {
            for msr in msrs.clone() {
                self.set(msr, allocfn(msr));
            }
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

        for msr in MSR_RANGE_MTRR_RANGE {
            bitmap
                .intercept(msr, InterceptMsrType::Disable)
                .unwrap_or_else(|_| {
                    panic!(
                        "error configuring MSR interception for MTRR Range MSR 0x{:x}",
                        msr
                    )
                });
        }

        bitmap
            .intercept(MSR_IA32_TIME_STAMP_COUNTER, InterceptMsrType::Write)
            .expect("error configuring MSR interception for TSC MSR");

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

    pub fn update_msr_bitmap_x2apic_apicv(&mut self) {
        let mut bitmap = self.new_bitmap_ref();

        for msr in MSR_RANGE_X2APIC {
            bitmap
                .intercept(msr, InterceptMsrType::Write)
                .unwrap_or_else(|_| {
                    panic!(
                        "error configuring MSR interception for x2APIC MSR 0x{:x}",
                        msr
                    )
                });
        }

        // Use read-only interception for write-only registers to inject #GP
        // on reads. EOI and Self-IPI writes are disabled for EOI, TPR and
        // Self-IPI as writes to them are virtualized with Register
        // Virtualization
        //
        // Refer to Section 29.1 in Intel SDM Vol. 3
        bitmap
            .intercept(MSR_IA32_EXT_APIC_CUR_COUNT, InterceptMsrType::Read)
            .expect("error configuring MSR interception for MSR_IA32_EXT_APIC_CUR_COUNT");
        bitmap
            .intercept(MSR_IA32_EXT_APIC_EOI, InterceptMsrType::Disable)
            .expect("error configuring MSR interception for MSR_IA32_EXT_APIC_EOI");
        bitmap
            .intercept(MSR_IA32_EXT_APIC_SELF_IPI, InterceptMsrType::Disable)
            .expect("error configuring MSR interception for MSR_IA32_EXT_APIC_SELF_IPI");
        bitmap
            .intercept(MSR_IA32_EXT_APIC_TPR, InterceptMsrType::Disable)
            .expect("error configuring MSR interception for MSR_IA32_EXT_APIC_TPR");
    }

    pub fn intercept(&mut self, msr: u32, inttype: InterceptMsrType) -> Result<(), TdxError> {
        let mut bitmap = self.new_bitmap_ref();
        bitmap.intercept(msr, inttype)
    }
}
