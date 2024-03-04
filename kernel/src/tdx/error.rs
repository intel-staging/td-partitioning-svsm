// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::ioreq::IoType;
use super::vmexit::VmExitReason;
use crate::address::GuestVirtAddr;
use crate::cpu::idt::common::PageFaultErrCode;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ErrExcp {
    GP(u32),
    PF(GuestVirtAddr, PageFaultErrCode),
    UD,
}

#[derive(Clone, Copy, Debug)]
pub enum TdxError {
    // Emulate Instruction related failure
    EmulInstr,
    // IO emulation related failure
    IoEmul(IoType),
    // IO emulation is not supported
    IoEmulNotSupport,
    // Guest fatal Error like triple fault
    GuestFatalErr,
    // Guest Page Table related failure
    GuestPGT,
    // Require to inject exception to Guest
    InjectExcp(ErrExcp),
    // Invalid AddrSize
    InvalidAddrSize,
    // Invalid code to translate to GuestCpuGPReg
    InvalidGPRegCode,
    // Invalid vector
    InvalidVector,
    // Invalid vm id
    InvalidVmId(u64),
    // Map Gpa failed
    MapGpa,
    // Failed to Map memory as private
    MapPrivate,
    // Failed to Map memory as shared
    MapShared,
    // Mem page attr wr failed
    MemPageAttrWr,
    // Accept memory related error
    PageAccept,
    // Read Guest Memory failed
    ReadGuestMem,
    // Sirte related failure
    Sirte,
    // Tdp guest is not supported
    TdpNotSupport,
    // Unaligned phys Address
    UnalignedPhysAddr,
    // Unsupported vmexit
    UnSupportedVmExit(VmExitReason),
    // Virtual ioapic related error
    Vioapic,
    // Virtual apic related error
    Vlapic,
    // Vm read related error
    VmRD(u64),
    // Vmsr related error
    Vmsr,
    // Vp write related error
    VpWR(u64, u64),
    // Write Guest Memory failed
    WriteGuestMem,
}
