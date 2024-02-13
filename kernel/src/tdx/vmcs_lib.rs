// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023-2024 Intel Corporation
// Copyright (C) 2023 Ant Group CO., Ltd. All rights reserved.
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

#![allow(dead_code)]

use super::tdcall::{tdcall_vp_read, tdcall_vp_write};
use super::utils::{build_tdg_field, field_elem_size, TdVpsPerVmClass, TdpVmId, MD_CONTEXT_VP};
use bitflags::bitflags;
use core::mem::size_of;

fn vmcs_class(vm_id: TdpVmId) -> u64 {
    TdVpsPerVmClass::Vmcs.code(vm_id)
}

fn vmcs_elem_size(bits: u8) -> u64 {
    field_elem_size(bits)
}

fn is_host_state_field(field: u32) -> bool {
    ((field >> 10) & 0x3) == 3
}

fn is_writable_field(field: u32) -> bool {
    match field {
        0x6 => true,                     //HLAT prefix size
        0x00000800..=0x00000810 => true, //GUEST_ES_SEL ... GUEST_INTR_STATUS
        0x00000814 => true,              //Guest UINV
        0x00002012..=0x00002013 => true, //VIRTUAL_APIC_PAGE_ADDR
        0x0000201A..=0x00002023 => true, //EPT_POINTER ... EOI_EXIT3
        0x0000202C..=0x0000202D => true, //XSS_EXITING_BITMAP ...  XSS_EXITING_BITMAP
        0x00002034..=0x00002035 => true, //PROC_VM_EXEC_CONTROLS3
        0x00002040 => true,              //HLAT pointer
        0x00002400..=0x00002401 => true, //GUEST_PHYSICAL_ADDR
        0x00002802..=0x00002811 => true, //GUEST_IA32_DEBUGCTL ... GUEST_PDPTE3
        0x00002814..=0x00002818 => true, //IA32_GUEST_PKRS
        0x00004002..=0x0000400a => true, //PROC_VM_EXEC_CONTROLS ... CR3_TARGET_COUNT
        0x00004012 => true,              //ENTRY_CONTROLS
        0x00004016..=0x00004022 => true, //ENTRY_INT_INFO_FIELD ... PLE_WINDOW
        0x00004400..=0x0000440e => true, //INSTR_ERROR ... INSTR_INFO
        0x00004800..=0x00004824 => true, //GUEST_ES_LIMIT ... GUEST_INTERRUPTIBILITY_INFO
        0x0000482a => true,              //GUEST_IA32_SYSENTER_CS
        0x00006000..=0x0000600e => true, //CR0_GUEST_HOST_MASK ... CR3_TARGET_3
        0x00006400..=0x0000640a => true, //EXIT_QUALIFICATION ... GUEST_LINEAR_ADDR
        0x00006800..=0x0000682c => true, //GUEST_CR0 ... INTR_SSP_TABLE
        _ => false,
    }
}

fn is_readonly_field(field: u32) -> bool {
    match field {
        0x00000002 => true,              //POSTED_INTR_VECTOR
        0x00002000..=0x00002003 => true, //IO_BITMAP_A ... IO_BITMAP_B
        0x00002016..=0x00002019 => true, //PIR_DESC_ADDR ... VM_FUNCTION_CTL
        0x0000202A..=0x0000202B => true, //VIR_EXCEPTION_INFO
        0x0000202e..=0x0000202f => true, //ENCLS_EXITING_BITMAP
        0x00002036 => true,              //ENCLV-Exiting Bitmap
        0x0000203c => true,              //SHARED_EPT_POINTER
        0x00004000 => true,              //PIN_VM_EXEC_CONTROLS
        0x0000400c => true,              //EXIT_CONTROLS
        0x00004024 => true,              //NOTIFY_WINDOW
        0x00004826 => true,              //GUEST_ACTIVITY_STATE
        _ => false,
    }
}

fn is_vp_enter_ctx_field(field: u32) -> bool {
    // These fields are passed to TDX module in tdg.vp.enter,
    // and don't need to write them in other places.
    // GUEST_RIP = 0x0000681e
    // GUEST_RFLAGS = 0x00006820
    field == 0x0000681e || field == 0x00006820
}

fn is_tdvps_vmcs_field_ignore_read(field: u32) -> bool {
    if is_host_state_field(field) {
        true
    } else {
        !is_writable_field(field) && !is_readonly_field(field)
    }
}

fn is_tdvps_vmcs_field_ignore_write(field: u32) -> bool {
    if is_host_state_field(field) || is_vp_enter_ctx_field(field) {
        true
    } else {
        !is_writable_field(field)
    }
}

const VMCS_ENC_ACCESS_TYPE_MASK: u32 = 0x1;
const VMCS_ENC_ACCESS_TYPE_HIGH: u32 = 0x1;
const VMCS_ENC_WIDTH_MASK: u32 = 0x6000;
const VMCS_ENC_WIDTH_16BIT: u32 = 0 << 13;
const VMCS_ENC_WIDTH_64BIT: u32 = 1 << 13;
const VMCS_ENC_WIDTH_32BIT: u32 = 2 << 13;
const VMCS_ENC_WIDTH_NATURAL: u32 = 3 << 13;

fn tdvps_vmcs_check(field: u32, bits: u8) {
    assert!(bits == 16 || bits == 32 || bits == 64);
    assert!((field & VMCS_ENC_ACCESS_TYPE_MASK) != VMCS_ENC_ACCESS_TYPE_HIGH);
    if bits == 64 {
        assert!(
            ((field & VMCS_ENC_WIDTH_MASK) == VMCS_ENC_WIDTH_64BIT)
                || ((field & VMCS_ENC_WIDTH_MASK) == VMCS_ENC_WIDTH_NATURAL)
        );
    }
    if bits == 32 {
        assert!((field & VMCS_ENC_WIDTH_MASK) == VMCS_ENC_WIDTH_32BIT);
    }
    if bits == 16 {
        assert!((field & VMCS_ENC_WIDTH_MASK) == VMCS_ENC_WIDTH_16BIT);
    }
}

fn tdvps_vmcs_write_mask(field: u32, bits: u8) -> u64 {
    match field {
        0x0000201A => 0x80,               //EPT_POINTER
        0x00002012 => 0xFFFFFFFFFFFFF000, //VIRTUAL_APIC_PAGE_ADDR
        0x00002040 => 0xFFFFFFFFFF018,    //Hypervisor-managed linear-address translation pointer
        0x00002802 => 0xFFC1,             //GUEST_IA32_DEBUGCTL
        0x00002806 => 0x501,              //GUEST_IA32_EFER
        0x00004002 => 0x48F99A04,         //PROC_VM_EXEC_CONTROLS
        0x00004004 => 0xFFFFFFFFFFFBFFFF, //EXCEPTION_BITMAP
        0x00004012 => 0x200,              //ENTRY_CONTROLS
        0x0000401E => 0xC513F0C,          //PROC_VM_EXEC_CONTROLS2
        0x00002034 => 0xE,                //PROC_VM_EXEC_CONTROLS3
        0x00006800 => 0x8005001F,         //GUEST_CR0
        0x00006804 => 0x3FF1FBF,          //GUEST_CR4
        _ => match bits {
            16 => 0xffff,
            32 => 0xffff_ffff,
            64 => 0xffff_ffff_ffff_ffff,
            _ => {
                panic!("vmcs_write_mask: not support bits {}", bits);
            }
        },
    }
}

fn vmread<T>(vm_id: TdpVmId, field: u32) -> T
where
    T: TryFrom<u64> + From<u16>,
{
    let bits = (size_of::<T>() * 8) as u8;

    if is_tdvps_vmcs_field_ignore_read(field) {
        return T::from(0u16);
    }

    tdvps_vmcs_check(field, bits);

    let field_id = build_tdg_field(
        vmcs_class(vm_id),
        MD_CONTEXT_VP,
        0,
        vmcs_elem_size(bits),
        field as u64,
    );
    match tdcall_vp_read(field_id) {
        Ok(ret) => match T::try_from(ret) {
            Ok(v) => v,
            Err(_e) => panic!("tdcall_vp_read got invalid result"),
        },
        Err(e) => {
            log::error!("tdcall_vp_read[{:#04x}] failed: {:?}", field, e);
            T::from(0u16)
        }
    }
}

fn vmwrite<T>(vm_id: TdpVmId, field: u32, value: T)
where
    T: Into<u64>,
{
    let bits = (size_of::<T>() * 8) as u8;

    if is_tdvps_vmcs_field_ignore_write(field) {
        return;
    }

    tdvps_vmcs_check(field, bits);

    let field_id = build_tdg_field(
        vmcs_class(vm_id),
        MD_CONTEXT_VP,
        1,
        vmcs_elem_size(bits),
        field as u64,
    );

    if let Err(e) = tdcall_vp_write(
        field_id,
        Into::<u64>::into(value),
        tdvps_vmcs_write_mask(field, bits),
    ) {
        log::error!("tdcall_vp_write[{:#04x}] failed: {:?}", field, e);
    }
}

pub trait VmcsAccess {
    type T;

    // All types implement VmcsAccess should implement read
    fn read(&self, vm_id: TdpVmId) -> Self::T;

    // Read-only types should not implement write.
    fn write(&self, _vm_id: TdpVmId, _value: Self::T) {
        log::error!("Write operation not supported");
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField16Control {
    VIRTUAL_PROCESSOR_ID = 0x00000000,
    POSTED_INTR_NV = 0x00000002,
    EPTP_INDEX = 0x00000004,
}

impl VmcsAccess for VmcsField16Control {
    type T = u16;
    fn read(&self, vm_id: TdpVmId) -> Self::T {
        vmread(vm_id, *self as u32)
    }
    fn write(&self, vm_id: TdpVmId, value: Self::T) {
        vmwrite(vm_id, *self as u32, value)
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField16Guest {
    ES_SELECTOR = 0x00000800,
    CS_SELECTOR = 0x00000802,
    SS_SELECTOR = 0x00000804,
    DS_SELECTOR = 0x00000806,
    FS_SELECTOR = 0x00000808,
    GS_SELECTOR = 0x0000080a,
    LDTR_SELECTOR = 0x0000080c,
    TR_SELECTOR = 0x0000080e,
    INTR_STATUS = 0x00000810,
    PML_INDEX = 0x00000812,
}

impl VmcsAccess for VmcsField16Guest {
    type T = u16;
    fn read(&self, vm_id: TdpVmId) -> Self::T {
        vmread(vm_id, *self as u32)
    }
    fn write(&self, vm_id: TdpVmId, value: Self::T) {
        vmwrite(vm_id, *self as u32, value)
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField16Host {
    ES_SELECTOR = 0x00000c00,
    CS_SELECTOR = 0x00000c02,
    SS_SELECTOR = 0x00000c04,
    DS_SELECTOR = 0x00000c06,
    FS_SELECTOR = 0x00000c08,
    GS_SELECTOR = 0x00000c0a,
    TR_SELECTOR = 0x00000c0c,
}

impl VmcsAccess for VmcsField16Host {
    type T = u16;
    fn read(&self, vm_id: TdpVmId) -> Self::T {
        vmread(vm_id, *self as u32)
    }
    fn write(&self, vm_id: TdpVmId, value: Self::T) {
        vmwrite(vm_id, *self as u32, value)
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField32Control {
    PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
    PROC_BASED_VM_EXEC_CONTROL = 0x00004002,
    EXCEPTION_BITMAP = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
    CR3_TARGET_COUNT = 0x0000400a,
    VM_EXIT_CONTROLS = 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
    VM_ENTRY_CONTROLS = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
    VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
    TPR_THRESHOLD = 0x0000401c,
    SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
    PLE_GAP = 0x00004020,
    PLE_WINDOW = 0x00004022,
}

impl VmcsAccess for VmcsField32Control {
    type T = u32;
    fn read(&self, vm_id: TdpVmId) -> Self::T {
        vmread(vm_id, *self as u32)
    }
    fn write(&self, vm_id: TdpVmId, value: Self::T) {
        vmwrite(vm_id, *self as u32, value)
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField32ReadOnly {
    VM_INSTRUCTION_ERROR = 0x00004400,
    VM_EXIT_REASON = 0x00004402,
    VM_EXIT_INTR_INFO = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE = 0x00004406,
    IDT_VECTORING_INFO_FIELD = 0x00004408,
    IDT_VECTORING_ERROR_CODE = 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
    VMX_INSTRUCTION_INFO = 0x0000440e,
}

impl VmcsAccess for VmcsField32ReadOnly {
    type T = u32;
    fn read(&self, vm_id: TdpVmId) -> Self::T {
        vmread(vm_id, *self as u32)
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum VmcsField32Guest {
    ES_LIMIT = 0x00004800,
    CS_LIMIT = 0x00004802,
    SS_LIMIT = 0x00004804,
    DS_LIMIT = 0x00004806,
    FS_LIMIT = 0x00004808,
    GS_LIMIT = 0x0000480a,
    LDTR_LIMIT = 0x0000480c,
    TR_LIMIT = 0x0000480e,
    GDTR_LIMIT = 0x00004810,
    IDTR_LIMIT = 0x00004812,
    ES_AR_BYTES = 0x00004814,
    CS_AR_BYTES = 0x00004816,
    SS_AR_BYTES = 0x00004818,
    DS_AR_BYTES = 0x0000481a,
    FS_AR_BYTES = 0x0000481c,
    GS_AR_BYTES = 0x0000481e,
    LDTR_AR_BYTES = 0x00004820,
    TR_AR_BYTES = 0x00004822,
    INTERRUPTIBILITY_INFO = 0x00004824,
    ACTIVITY_STATE = 0x00004826,
    SMBASE = 0x00004828,
    SYSENTER_CS = 0x0000482A,
    VMX_PREEMPTION_TIMER_VALUE = 0x0000482E,
}

impl VmcsAccess for VmcsField32Guest {
    type T = u32;
    fn read(&self, vm_id: TdpVmId) -> Self::T {
        vmread(vm_id, *self as u32)
    }
    fn write(&self, vm_id: TdpVmId, value: Self::T) {
        vmwrite(vm_id, *self as u32, value)
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField32Host {
    IA32_SYSENTER_CS = 0x00004c00,
}

impl VmcsAccess for VmcsField32Host {
    type T = u32;
    fn read(&self, vm_id: TdpVmId) -> Self::T {
        vmread(vm_id, *self as u32)
    }
    fn write(&self, vm_id: TdpVmId, value: Self::T) {
        vmwrite(vm_id, *self as u32, value)
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField64Control {
    IO_BITMAP_A = 0x00002000,
    IO_BITMAP_B = 0x00002002,
    MSR_BITMAP = 0x00002004,
    VM_EXIT_MSR_STORE_ADDR = 0x00002006,
    VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
    VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
    EXECUTIVE_VMCS_PTR = 0x0000200c,
    PML_ADDRESS = 0x0000200e,
    TSC_OFFSET = 0x00002010,
    VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
    APIC_ACCESS_ADDR = 0x00002014,
    POSTED_INTR_DESC_ADDR = 0x00002016,
    VM_FUNCTION_CONTROL = 0x00002018,
    EPT_POINTER = 0x0000201a,
    EOI_EXIT_BITMAP0 = 0x0000201c,
    EOI_EXIT_BITMAP1 = 0x0000201e,
    EOI_EXIT_BITMAP2 = 0x00002020,
    EOI_EXIT_BITMAP3 = 0x00002022,
    EPTP_LIST_ADDRESS = 0x00002024,
    VMREAD_BITMAP = 0x00002026,
    VMWRITE_BITMAP = 0x00002028,
    XSS_EXIT_BITMAP = 0x0000202c,
    ENCLS_EXITING_BITMAP = 0x0000202e,
    TSC_MULTIPLIER = 0x00002032,
    TERTIARY_VM_EXEC_CONTROL = 0x00002034,

    // Natural Width
    CR0_GUEST_HOST_MASK = 0x00006000,
    CR4_GUEST_HOST_MASK = 0x00006002,
    CR0_READ_SHADOW = 0x00006004,
    CR4_READ_SHADOW = 0x00006006,
    CR3_TARGET_VALUE0 = 0x00006008,
    CR3_TARGET_VALUE1 = 0x0000600a,
    CR3_TARGET_VALUE2 = 0x0000600c,
    CR3_TARGET_VALUE3 = 0x0000600e,
}

impl VmcsAccess for VmcsField64Control {
    type T = u64;
    fn read(&self, vm_id: TdpVmId) -> Self::T {
        vmread(vm_id, *self as u32)
    }
    fn write(&self, vm_id: TdpVmId, value: Self::T) {
        vmwrite(vm_id, *self as u32, value)
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum VmcsField64ReadOnly {
    GUEST_PHYSICAL_ADDRESS = 0x00002400,

    // Natural Width
    EXIT_QUALIFICATION = 0x00006400,
    IO_RCX = 0x00006402,
    IO_RSI = 0x00006404,
    IO_RDI = 0x00006406,
    IO_RIP = 0x00006408,
    GUEST_LINEAR_ADDRESS = 0x0000640a,
}

impl VmcsAccess for VmcsField64ReadOnly {
    type T = u64;
    fn read(&self, vm_id: TdpVmId) -> Self::T {
        vmread(vm_id, *self as u32)
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum VmcsField64Guest {
    VMCS_LINK_POINTER = 0x00002800,
    IA32_DEBUGCTL = 0x00002802,
    IA32_PAT = 0x00002804,
    IA32_EFER = 0x00002806,
    IA32_PERF_GLOBAL_CTRL = 0x00002808,
    PDPTR0 = 0x0000280a,
    PDPTR1 = 0x0000280c,
    PDPTR2 = 0x0000280e,
    PDPTR3 = 0x00002810,
    BNDCFGS = 0x00002812,

    // Natural Width
    CR0 = 0x00006800,
    CR3 = 0x00006802,
    CR4 = 0x00006804,
    ES_BASE = 0x00006806,
    CS_BASE = 0x00006808,
    SS_BASE = 0x0000680a,
    DS_BASE = 0x0000680c,
    FS_BASE = 0x0000680e,
    GS_BASE = 0x00006810,
    LDTR_BASE = 0x00006812,
    TR_BASE = 0x00006814,
    GDTR_BASE = 0x00006816,
    IDTR_BASE = 0x00006818,
    DR7 = 0x0000681a,
    RSP = 0x0000681c,
    RIP = 0x0000681e,
    RFLAGS = 0x00006820,
    PENDING_DBG_EXCEPTIONS = 0x00006822,
    SYSENTER_ESP = 0x00006824,
    SYSENTER_EIP = 0x00006826,
}

impl VmcsAccess for VmcsField64Guest {
    type T = u64;
    fn read(&self, vm_id: TdpVmId) -> Self::T {
        vmread(vm_id, *self as u32)
    }
    fn write(&self, vm_id: TdpVmId, value: Self::T) {
        vmwrite(vm_id, *self as u32, value)
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum VmcsField64Host {
    IA32_PAT = 0x00002c00,
    IA32_EFER = 0x00002c02,
    IA32_PERF_GLOBAL_CTRL = 0x00002c04,

    // Natural Width
    CR0 = 0x00006c00,
    CR3 = 0x00006c02,
    CR4 = 0x00006c04,
    FS_BASE = 0x00006c06,
    GS_BASE = 0x00006c08,
    TR_BASE = 0x00006c0a,
    GDTR_BASE = 0x00006c0c,
    IDTR_BASE = 0x00006c0e,
    IA32_SYSENTER_ESP = 0x00006c10,
    IA32_SYSENTER_EIP = 0x00006c12,
    RSP = 0x00006c14,
    RIP = 0x00006c16,
}

impl VmcsAccess for VmcsField64Host {
    type T = u64;
    fn read(&self, vm_id: TdpVmId) -> Self::T {
        vmread(vm_id, *self as u32)
    }
    fn write(&self, vm_id: TdpVmId, value: Self::T) {
        vmwrite(vm_id, *self as u32, value)
    }
}

bitflags! {
    /// 24.6.1 Pin-Based VM-Execution Controls.
    pub struct PinVmExecControls: u32 {
        /// VM-Exit on vectored interrupts
        #[allow(clippy::identity_op)]
        const INTR_EXITING      = 1 << 0;
        /// VM-Exit on NMIs
        const NMI_EXITING       = 1 << 3;
        /// NMI virtualization
        const VIRTUAL_NMIS      = 1 << 5;
        /// VMX Preemption Timer
        const PREEMPTION_TIMER  = 1 << 6;
        /// Posted Interrupts
        const POSTED_INTR       = 1 << 7;
    }
}

bitflags! {
    /// 24.6.2 Primary Processor-Based VM-Execution Controls.
    pub struct PrimaryVmExecControls: u32 {
        /// VM-Exit if INTRs are unblocked in guest
        const INTR_WINDOW_EXITING   = 1 <<  2;
        /// Offset hardware TSC when read in guest
        const USE_TSC_OFFSETTING    = 1 <<  3;
        /// VM-Exit on HLT
        const HLT_EXITING           = 1 <<  7;
        /// VM-Exit on INVLPG
        const INVLPG_EXITING        = 1 <<  9;
        /// VM-Exit on MWAIT
        const MWAIT_EXITING         = 1 << 10;
        /// VM-Exit on RDPMC
        const RDPMC_EXITING         = 1 << 11;
        /// VM-Exit on RDTSC
        const RDTSC_EXITING         = 1 << 12;
        /// VM-Exit on writes to CR3
        const CR3_LOAD_EXITING      = 1 << 15;
        /// VM-Exit on reads from CR3
        const CR3_STORE_EXITING     = 1 << 16;
        /// Enable Tertiary VM-Execution Controls
        const TERTIARY_CONTROLS     = 1 << 17;
        /// VM-Exit on writes to CR8
        const CR8_LOAD_EXITING      = 1 << 19;
        /// VM-Exit on reads from CR8
        const CR8_STORE_EXITING     = 1 << 20;
        /// TPR virtualization, a.k.a. TPR shadow
        const VIRTUAL_TPR           = 1 << 21;
        /// VM-Exit if NMIs are unblocked in guest
        const NMI_WINDOW_EXITING    = 1 << 22;
        /// VM-Exit on accesses to debug registers
        const MOV_DR_EXITING        = 1 << 23;
        /// VM-Exit on *all* IN{S} and OUT{S}
        const UNCOND_IO_EXITING     = 1 << 24;
        /// VM-Exit based on I/O port
        const USE_IO_BITMAPS        = 1 << 25;
        /// VMX single-step VM-Exits
        const MONITOR_TRAP_FLAG     = 1 << 27;
        /// VM-Exit based on MSR index
        const USE_MSR_BITMAPS       = 1 << 28;
        /// M-Exit on MONITOR (MWAIT's accomplice)
        const MONITOR_EXITING       = 1 << 29;
        /// VM-Exit on PAUSE (unconditionally)
        const PAUSE_EXITING         = 1 << 30;
        /// Enable Secondary VM-Execution Controls
        const SEC_CONTROLS          = 1 << 31;
    }
}

bitflags! {
    /// 24.6.2 Secondary Primary Processor-Based VM-Execution Controls.
    pub struct SecondaryVmExecControls: u32 {
        /// Virtualize memory mapped APIC accesses
        #[allow(clippy::identity_op)]
        const VIRT_APIC_ACCESSES    = 1 <<  0;
        /// Extended Page Tables, a.k.a. Two-Dimensional Paging
        const EPT                   = 1 <<  1;
        /// VM-Exit on {S,L}*DT instructions
        const DESC_EXITING          = 1 <<  2;
        /// Enable RDTSCP in guest
        const RDTSCP                = 1 <<  3;
        /// Virtualize X2APIC for the guest
        const VIRTUAL_X2APIC        = 1 <<  4;
        /// Virtual Processor ID (TLB ASID modifier)
        const VPID                  = 1 <<  5;
        /// VM-Exit on WBINVD
        const WBINVD_EXITING        = 1 <<  6;
        /// Allow Big Real Mode and other "invalid" states
        const UNRESTRICTED_GUEST    = 1 <<  7;
        /// Hardware emulation of reads to the virtual-APIC
        const APIC_REGISTER_VIRT    = 1 <<  8;
        /// Evaluation and delivery of pending virtual interrupts
        const VIRT_INTR_DELIVERY    = 1 <<  9;
        /// Conditionally VM-Exit on PAUSE at CPL0
        const PAUSE_LOOP_EXITING    = 1 << 10;
        /// VM-Exit on RDRAND
        const RDRAND_EXITING        = 1 << 11;
        /// Enable INVPCID in guest
        const INVPCID               = 1 << 12;
        /// Enable VM-Functions (leaf dependent)
        const VMFUNC                = 1 << 13;
        /// VMREAD/VMWRITE in guest can access shadow VMCS
        const SHADOW_VMCS           = 1 << 14;
        /// VM-Exit on ENCLS (leaf dependent)
        const ENCLS_EXITING         = 1 << 15;
        /// VM-Exit on RDSEED
        const RDSEED_EXITING        = 1 << 16;
        /// Log dirty pages into buffer
        const PAGE_MOD_LOGGING      = 1 << 17;
        /// Conditionally reflect EPT violations as #VE exceptions
        const EPT_VIOLATION_VE      = 1 << 18;
        /// Suppress VMX indicators in Processor Trace
        const PT_CONCEAL_VMX        = 1 << 19;
        /// Enable XSAVES and XRSTORS in guest
        const XSAVES                = 1 << 20;
        /// Enable separate EPT EXEC bits for supervisor vs. user
        const MODE_BASED_EPT_EXEC   = 1 << 22;
        /// Processor Trace logs GPAs
        const PT_USE_GPA            = 1 << 24;
        /// Scale hardware TSC when read in guest
        const TSC_SCALING           = 1 << 25;
        /// Enable TPAUSE, UMONITOR, UMWAIT in guest
        const USR_WAIT_PAUSE        = 1 << 26;
        /// VM-Exit on ENCLV (leaf dependent)
        const ENCLV_EXITING         = 1 << 28;
    }
}

bitflags! {
    pub struct TertiaryVmExecControls: u64 {
        /// KeyLocker LoadIWKey.
        const LOADIWKEY    = 1 <<  0;
    }
}

bitflags! {
    /// 24.7.1 VM-Exit Controls.
    pub struct VmExitControls: u32 {
        const SAVE_DEBUG_CONTROLS           = 1 <<  2;
        /// Logical processor is in 64-bit mode after VM exit.
        const HOST_ADDR_SPACE_SIZE          = 1 <<  9;
        const LOAD_IA32_PERF_GLOBAL_CTRL    = 1 << 12;
        /// Acknowledge external interrupt on exit.
        const ACK_INTR_ON_EXIT              = 1 << 15;
        /// Save the guest IA32_PAT MSR on exit.
        const SAVE_IA32_PAT                 = 1 << 18;
        /// Load the guest IA32_PAT MSR on exit.
        const LOAD_IA32_PAT                 = 1 << 19;
        /// Save the guest IA32_EFER MSR on exit.
        const SAVE_IA32_EFER                = 1 << 20;
        /// Load the host IA32_EFER MSR on exit.
        const LOAD_IA32_EFER                = 1 << 21;
        const SAVE_VMX_PREEMPTION_TIMER     = 1 << 22;
        const CLEAR_BNDCFGS                 = 1 << 23;
        const PT_CONCEAL_PIP                = 1 << 24;
        const CLEAR_IA32_RTIT_CTL           = 1 << 25;
        const LOAD_CET_STATE                = 1 << 28;
    }
}

bitflags! {
    /// 24.8.1 VM-Entry Controls.
    pub struct VmEntryControls: u32 {
        const LOAD_DEBUG_CONTROLS           = 1 <<  2;
        const IA32E_MODE                    = 1 <<  9;
        const SMM                           = 1 << 10;
        const DEACT_DUAL_MONITOR            = 1 << 11;
        const LOAD_IA32_PERF_GLOBAL_CTRL    = 1 << 13;
        /// Load the guest IA32_PAT MSR on entry.
        const LOAD_IA32_PAT                 = 1 << 14;
        /// Load the guest IA32_EFER MSR on entry.
        const LOAD_IA32_EFER                = 1 << 15;
        const LOAD_BNDCFGS                  = 1 << 16;
        const PT_CONCEAL_PIP                = 1 << 17;
        const LOAD_IA32_RTIT_CTL            = 1 << 18;
        const LOAD_CET_STATE                = 1 << 20;
    }
}

// VMX Interrupt info
pub const VMX_INT_INFO_VALID: u32 = 1 << 31;
pub const VMX_INT_TYPE_NMI: u32 = 2 << 8;
pub const VMX_INT_TYPE_HW_EXCP: u32 = 3 << 8;
pub const VMX_INT_TYPE_SW_EXCP: u32 = 6 << 8;
pub const VMX_INT_TYPE_MASK: u32 = 7 << 8;
pub const VMX_INT_INFO_ERR_CODE_VALID: u32 = 1 << 11;

// VMX Interruptability info
pub const VMX_INTERRUPTABILITY_VCPU_BLOCKED_BY_NMI: u32 = 1 << 3;
pub const VMX_INTERRUPTABILITY_VCPU_BLOCKED_BY_MOVSS: u32 = 1 << 1;
pub const VMX_INTERRUPTABILITY_VCPU_BLOCKED_BY_STI: u32 = 1 << 0;
