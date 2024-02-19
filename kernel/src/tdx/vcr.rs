// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::error::{ErrExcp, TdxError};
use super::gctx::RegCache;
use super::percpu::{this_vcpu, this_vcpu_mut};
use super::utils::TdpVmId;
use super::vmcs_lib::{VmEntryControls, VmcsField32Control, VmcsField64Control, VmcsField64Guest};
use crate::cpu::control_regs::{read_cr2, write_cr2, CR0Flags, CR4Flags};
use crate::cpu::efer::EFERFlags;
use crate::cpu::msr::{
    read_msr, MSR_IA32_VMX_CR0_FIXED0, MSR_IA32_VMX_CR0_FIXED1, MSR_IA32_VMX_CR4_FIXED0,
    MSR_IA32_VMX_CR4_FIXED1,
};
use crate::utils::immut_after_init::ImmutAfterInitCell;
use lazy_static::lazy_static;

// Physical CR4 bits in VMX operation may be either flexible or fixed.
// Guest CR4 bits may be operatable or reserved.
//
// All the guest reserved bits should be TRAPed and EMULATed by HV
// (inject #GP).
//
// For guest operatable bits, it may be:
// CR4_PASSTHRU_FLAGS:
//      Bits that may be passed through to guest. The actual passthru bits
//      should be masked by flexible bits.
//
// CR4_TRAP_AND_PASSTHRU_FLAGS:
//      The bits are trapped by HV and HV emulation will eventually write
//      the guest value to physical CR4 (GUEST_CR4) too. The actual bits
//      should be masked by flexible bits.
//
// CR4_TRAP_AND_EMULATE_FLAGS:
//      The bits are trapped by HV and emulated, but HV updates vCR4 only
//      (no update to physical CR4), i.e. pure software emulation.
//
// CR4_EMRSV_FLAGS:
//      The bits are trapped, but are emulated by injecting a #GP.
//
// NOTE: Above bits should not overlap.

lazy_static! {
    static ref CR4_PASSTHROUGH_FLAGS: CR4Flags= CR4Flags::VME
        | CR4Flags::PVI
        | CR4Flags::TSD
        | CR4Flags::DE
        | CR4Flags::PGE
        | CR4Flags::PCE
        | CR4Flags::OSFXSR
        | CR4Flags::OSXMMEXCPT
        | CR4Flags::UMIP
        | CR4Flags::LA57
        | CR4Flags::FSGSBASE
        | CR4Flags::PCIDE
        | CR4Flags::OSXSAVE;
    static ref CR4_TRAP_PASSTHROUGH_FLAGS : CR4Flags= CR4Flags::PSE
        | CR4Flags::PAE
        | CR4Flags::SMEP
        | CR4Flags::SMAP;
    static ref CR4_TRAP_EMULATE_FLAGS: CR4Flags = CR4Flags::MCE;
    static ref CR4_EMRSV_FLAGS: CR4Flags = CR4Flags::VMXE
        | CR4Flags::SMXE
        | CR4Flags::KL
        | CR4Flags::CET
        | CR4Flags::PKE
        | CR4Flags::PKS;
    // The physical CR4 value for bits of CR4_EMRSV_FLAGS
    static ref CR4_EMRSV_PHYS_FLAGS: CR4Flags = CR4Flags::VMXE;
    // The CR4 value guest expected to see for bits of CR4_EMRSV_FLAGS
    static ref CR4_EMRSV_VIRT_FLAGS: CR4Flags = CR4Flags::empty();

    // CR0 follows the same rules with CR4
    static ref CR0_PASSTHROUGH_FLAGS: CR0Flags = CR0Flags::MP
        | CR0Flags::EM
        | CR0Flags::TS
        | CR0Flags::ET
        | CR0Flags::NE
        | CR0Flags::AM;
    static ref CR0_TRAP_PASSTHROUGH_FLAGS: CR0Flags = CR0Flags::PE
        | CR0Flags::PG
        | CR0Flags::WP;
    static ref CR0_TRAP_EMULATE_FLAGS: CR0Flags = CR0Flags::CD | CR0Flags::NW;
    static ref CR0_EMRSV_FLAGS: CR0Flags = CR0Flags::empty();
    static ref CR0_EMRSV_PHYS_FLAGS: CR0Flags = CR0Flags::empty();
    static ref CR0_EMRSV_VIRT_FLAGS: CR0Flags = CR0Flags::empty();
}

#[derive(Copy, Clone, Debug)]
struct CrConfigs {
    pt_mask: u64,
    trap_pt_mask: u64,
    reserved_mask: u64,
    reserved_guest_bits: u64,
    initial_guest_bits: u64,
}

static CR0_CONFIGS: ImmutAfterInitCell<CrConfigs> = ImmutAfterInitCell::uninit();
static CR4_CONFIGS: ImmutAfterInitCell<CrConfigs> = ImmutAfterInitCell::uninit();
static SETUP: ImmutAfterInitCell<bool> = ImmutAfterInitCell::new(false);

fn init_cr4_configs() -> CrConfigs {
    // Make sure these bits doesn't have any overlap
    assert!(
        (*CR4_PASSTHROUGH_FLAGS ^ *CR4_TRAP_PASSTHROUGH_FLAGS ^ *CR4_TRAP_EMULATE_FLAGS)
            == (*CR4_PASSTHROUGH_FLAGS | *CR4_TRAP_PASSTHROUGH_FLAGS | *CR4_TRAP_EMULATE_FLAGS)
    );

    let fixed0 = CR4Flags::from_bits_retain(read_msr(MSR_IA32_VMX_CR4_FIXED0).unwrap());
    let fixed1 = CR4Flags::from_bits_retain(read_msr(MSR_IA32_VMX_CR4_FIXED1).unwrap());
    let flexible = fixed0 ^ fixed1;
    let pt_mask = (*CR4_PASSTHROUGH_FLAGS & flexible).bits();
    let trap_pt_mask = (*CR4_TRAP_PASSTHROUGH_FLAGS & flexible).bits();
    let reserved_mask = !(pt_mask | trap_pt_mask | CR4_TRAP_EMULATE_FLAGS.bits());
    let reserved_guest_bits = fixed0
        .difference(*CR4_TRAP_EMULATE_FLAGS | *CR4_EMRSV_FLAGS)
        .union(*CR4_EMRSV_VIRT_FLAGS)
        .bits();
    let initial_guest_bits = fixed0
        .difference(*CR4_EMRSV_FLAGS)
        .union(*CR4_EMRSV_PHYS_FLAGS)
        .bits();

    CrConfigs {
        pt_mask,
        trap_pt_mask,
        reserved_mask,
        reserved_guest_bits,
        initial_guest_bits,
    }
}

fn init_cr0_configs() -> CrConfigs {
    // Make sure these bits doesn't have any overlap
    assert!(
        (*CR0_PASSTHROUGH_FLAGS ^ *CR0_TRAP_PASSTHROUGH_FLAGS ^ *CR0_TRAP_EMULATE_FLAGS)
            == (*CR0_PASSTHROUGH_FLAGS | *CR0_TRAP_PASSTHROUGH_FLAGS | *CR0_TRAP_EMULATE_FLAGS)
    );

    // Needs PG/PE for unrestriced guest
    let fixed0 = CR0Flags::from_bits_retain(read_msr(MSR_IA32_VMX_CR0_FIXED0).unwrap());
    let fixed1 = CR0Flags::from_bits_retain(read_msr(MSR_IA32_VMX_CR0_FIXED1).unwrap());
    let flexible = fixed0 ^ fixed1 | CR0Flags::PE | CR0Flags::PG;
    let pt_mask = (*CR0_PASSTHROUGH_FLAGS & flexible).bits();
    let trap_pt_mask = (*CR0_TRAP_PASSTHROUGH_FLAGS & flexible).bits();
    let reserved_mask = !(pt_mask | trap_pt_mask | CR0_TRAP_EMULATE_FLAGS.bits());
    let reserved_guest_bits = fixed0
        .difference(*CR0_TRAP_EMULATE_FLAGS | *CR0_EMRSV_FLAGS)
        .union(*CR0_EMRSV_VIRT_FLAGS)
        .bits();
    let initial_guest_bits = fixed0
        .difference(*CR0_EMRSV_FLAGS)
        .union(*CR0_EMRSV_PHYS_FLAGS)
        .bits();

    CrConfigs {
        pt_mask,
        trap_pt_mask,
        reserved_mask,
        reserved_guest_bits,
        initial_guest_bits,
    }
}

fn init_cr0_cr4_configs() {
    if !*SETUP {
        let _ = CR0_CONFIGS.init(&init_cr0_configs());
        let _ = CR4_CONFIGS.init(&init_cr4_configs());
        SETUP.reinit(&true);
    }
}

pub struct GuestCpuCrRegs {
    cr0: RegCache<u64>,
    cr2: RegCache<u64>,
    cr3: RegCache<u64>,
    cr4: RegCache<u64>,
}

impl GuestCpuCrRegs {
    pub fn init(&mut self, vm_id: TdpVmId) {
        init_cr0_cr4_configs();

        self.cr0 = RegCache::new(
            vm_id,
            Some(|vmcs| {
                (vmcs.read64(VmcsField64Guest::CR0) & CR0_CONFIGS.pt_mask)
                    | (vmcs.read64(VmcsField64Control::CR0_READ_SHADOW) & !CR0_CONFIGS.pt_mask)
            }),
            Some(|vmcs, v| {
                let mask = CR0_CONFIGS.pt_mask | CR0_CONFIGS.trap_pt_mask;
                let hw_cr0 = CR0_CONFIGS.initial_guest_bits & !mask | (v & mask);
                vmcs.write64(VmcsField64Guest::CR0, hw_cr0);
                vmcs.write64(VmcsField64Control::CR0_READ_SHADOW, v);
            }),
        );
        self.cr2 = RegCache::new(
            vm_id,
            Some(|_| read_cr2() as u64),
            Some(|_, v| {
                if v != (read_cr2() as u64) {
                    write_cr2(v as usize)
                }
            }),
        );
        self.cr3 = RegCache::new(
            vm_id,
            Some(|vmcs| vmcs.read64(VmcsField64Guest::CR3)),
            Some(|vmcs, v| vmcs.write64(VmcsField64Guest::CR3, v)),
        );
        self.cr4 = RegCache::new(
            vm_id,
            Some(|vmcs| {
                (vmcs.read64(VmcsField64Guest::CR4) & CR4_CONFIGS.pt_mask)
                    | (vmcs.read64(VmcsField64Control::CR4_READ_SHADOW) & !CR4_CONFIGS.pt_mask)
            }),
            Some(|vmcs, v| {
                let mask = CR4_CONFIGS.pt_mask | CR4_CONFIGS.trap_pt_mask;
                let hw_cr4 = CR4_CONFIGS.initial_guest_bits & !mask | (v & mask);
                vmcs.write64(VmcsField64Guest::CR4, hw_cr4);
                vmcs.write64(VmcsField64Control::CR4_READ_SHADOW, v);
            }),
        );
    }

    fn is_valid_cr0(&self, v: u64) -> bool {
        (v & CR0_CONFIGS.reserved_mask) == CR0_CONFIGS.reserved_guest_bits
    }

    fn is_valid_cr4(&self, v: u64) -> bool {
        (v & CR4_CONFIGS.reserved_mask) == CR4_CONFIGS.reserved_guest_bits
    }

    fn get_effective_cr0(
        &self,
        val: u64,
        cr4: CR4Flags,
        efer: EFERFlags,
    ) -> Result<CR0Flags, TdxError> {
        if !self.is_valid_cr0(val) {
            log::error!("Set CR0 val 0x{:x} invalid", val);
            return Err(TdxError::InjectExcp(ErrExcp::GP(0)));
        }

        // SDM Vol2
        // Attempting to set any reserved bits in CR0[31:0] is ignored.
        // Attempting to set any reserved bits in CR0[63:32] results in a
        // general-protection exception, #GP(0).
        if (val >> 32) != 0 {
            log::error!("Set CR0 bit[63:32]: 0x{:x} result #GP", val);
            return Err(TdxError::InjectExcp(ErrExcp::GP(0)));
        }

        // Ignore any reserved bits in [31: 0]
        let cr0 = CR0Flags::from_bits_truncate(val);

        // SDM vol3 26.3 "Changes to instruction behavior in VMX non-root"
        //
        // "unrestricted guest" control is required and enabled.
        // Below cases cause  #GP
        // CR0.PE = 0 and CR0.PG = 1.
        // CR0.PG = 1, CR4.PAE = 0 and IA32_EFER.LME = 1
        if !cr0.contains(CR0Flags::PE) && cr0.contains(CR0Flags::PG) {
            log::error!("Set CR0 PE = 0, PG = 1 result #GP");
            return Err(TdxError::InjectExcp(ErrExcp::GP(0)));
        }

        if cr0.contains(CR0Flags::PG)
            && !cr4.contains(CR4Flags::PAE)
            && efer.contains(EFERFlags::LME)
        {
            log::error!("Set PG = 1 when CR4.PAE = 0 and IA32_EFER.LME = 1 result #GP");
            return Err(TdxError::InjectExcp(ErrExcp::GP(0)));
        }

        // SDM Vol3 6.15 "Exception and Interrupt Refrerence" GP Exception
        //
        // Loading the CR0 register with a set NW flag and a clear CD flag
        if !cr0.contains(CR0Flags::CD) && cr0.contains(CR0Flags::NW) {
            log::error!("Set CR0 CD = 0, NW = 1 result #GP");
            return Err(TdxError::InjectExcp(ErrExcp::GP(0)));
        }

        // SDM Vol3 4.10.1 "Process-Context Identifiers (PCIDs)"
        //
        // MOV to CR0 causes a general-protection exception if it would
        // clear CR0.PG to 0 while CR4.PCIDE = 1
        if !cr0.contains(CR0Flags::PG) && cr4.contains(CR4Flags::PCIDE) {
            log::error!("Set CR0 PG = 0 while CR4.PCIDE = 1 result #GP");
            return Err(TdxError::InjectExcp(ErrExcp::GP(0)));
        }

        Ok(cr0)
    }

    pub fn get_cr0(&self) -> u64 {
        self.cr0.read_cache()
    }

    pub fn set_cr0(&mut self, val: u64) -> Result<(), TdxError> {
        let vm_id = self.cr0.vm_id();
        let vmcs = this_vcpu(vm_id).get_vmcs();
        let ctx = this_vcpu_mut(vm_id).get_ctx_mut();

        let cr4 = CR4Flags::from_bits_truncate(self.get_cr4());
        let efer = EFERFlags::from_bits_retain(ctx.get_efer());
        let effective_cr0 = self.get_effective_cr0(val, cr4, efer)?;
        let changed_cr0 = CR0Flags::from_bits(self.get_cr0()).unwrap() ^ effective_cr0;

        if changed_cr0.contains(CR0Flags::PG) {
            // PG bit changed
            if effective_cr0.contains(CR0Flags::PG) {
                // Enable PG
                if efer.contains(EFERFlags::LME) {
                    // Enable long mode
                    let entry_ctrls = vmcs.read32(VmcsField32Control::VM_ENTRY_CONTROLS);
                    vmcs.write32(
                        VmcsField32Control::VM_ENTRY_CONTROLS,
                        entry_ctrls | VmEntryControls::IA32E_MODE.bits(),
                    );
                    ctx.set_efer((efer | EFERFlags::LMA).bits());
                } else if cr4.contains(CR4Flags::PAE) {
                    // TODO: Enable PAE by load PDPTR
                }
            } else {
                // Disable PG
                if efer.contains(EFERFlags::LME) {
                    // Disable long mode
                    let entry_ctrls = vmcs.read32(VmcsField32Control::VM_ENTRY_CONTROLS);
                    vmcs.write32(
                        VmcsField32Control::VM_ENTRY_CONTROLS,
                        entry_ctrls & !VmEntryControls::IA32E_MODE.bits(),
                    );
                    ctx.set_efer((efer & !EFERFlags::LMA).bits());
                }
            }
        }

        if changed_cr0.contains(CR0Flags::PG | CR0Flags::WP | CR0Flags::CD) {
            // TODO: Handle MSR_IA32_PAT and Flush EPT
        }

        self.cr0.write_cache(effective_cr0.bits());

        Ok(())
    }

    fn get_effective_cr4(&self, val: u64, efer: EFERFlags) -> Result<CR4Flags, TdxError> {
        if !self.is_valid_cr4(val) {
            log::error!("Set CR4 val 0x{:x} invalid", val);
            return Err(TdxError::InjectExcp(ErrExcp::GP(0)));
        }

        // Convert val to CR4Flags, and panic if val
        // contains undefined bits
        let cr4 = CR4Flags::from_bits(val).unwrap();

        if efer.contains(EFERFlags::LMA) && !cr4.contains(CR4Flags::PAE) {
            log::error!("Set CR4 with PAE = 0 while EFER.LMA = 1 result #GP");
            return Err(TdxError::InjectExcp(ErrExcp::GP(0)));
        }

        Ok(cr4)
    }

    pub fn get_cr4(&self) -> u64 {
        self.cr4.read_cache()
    }

    pub fn set_cr4(&mut self, val: u64) -> Result<(), TdxError> {
        let vm_id = self.cr4.vm_id();
        let ctx = this_vcpu(vm_id).get_ctx();

        let efer = EFERFlags::from_bits_truncate(ctx.get_efer());
        let effective_cr4 = self.get_effective_cr4(val, efer)?;
        let changed_cr4 = CR4Flags::from_bits(self.get_cr4()).unwrap() ^ effective_cr4;

        if changed_cr4.contains(*CR4_TRAP_PASSTHROUGH_FLAGS) {
            // TODO: Flush EPT
            if effective_cr4.contains(CR4Flags::PAE)
                && CR0Flags::from_bits_truncate(self.get_cr0()).contains(CR0Flags::PG)
                && !efer.contains(EFERFlags::LMA)
            {
                // TODO: Enable PAE
            }
        }

        if changed_cr4.contains(CR4Flags::PCIDE) {
            // MOV to CR4 causes a general-protection exception (#GP) if it would change
            // CR4.PCIDE from 0 to 1 and either IA32_EFER.LMA = 0 or CR3[11:0] != 000H
            if effective_cr4.contains(CR4Flags::PCIDE)
                && (!efer.contains(EFERFlags::LMA) || (self.get_cr3() & 0xFFF != 0))
            {
                log::error!("Set CR4.PCIDE from 0 to 1 with EFER.LMA = 0 or CR[11:0] != 0");
                return Err(TdxError::InjectExcp(ErrExcp::GP(0)));
            }
        }

        self.cr4.write_cache(effective_cr4.bits());

        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_cr2(&self) -> u64 {
        self.cr2.read_cache()
    }

    pub fn set_cr2(&mut self, val: u64) -> Result<(), TdxError> {
        self.cr2.write_cache(val);

        Ok(())
    }

    pub fn get_cr3(&self) -> u64 {
        self.cr3.read_cache()
    }

    pub fn set_cr3(&mut self, val: u64) -> Result<(), TdxError> {
        self.cr3.write_cache(val);

        Ok(())
    }

    #[allow(dead_code)]
    pub fn load(&mut self) {
        self.cr0.sync_cache();
        self.cr2.sync_cache();
        self.cr3.sync_cache();
        self.cr4.sync_cache();
    }
}
