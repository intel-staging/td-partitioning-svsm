// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ErrExcp {
    GP(u32),
    UD,
}

#[derive(Clone, Copy, Debug)]
pub enum TdxError {
    // Require to inject exception to Guest
    InjectExcp(ErrExcp),
    // Invalid vm id
    InvalidVmId(u64),
    // Map Gpa failed
    MapGpa,
    // Failed to Map memory as private
    MapPrivate,
    // Failed to Map memory as shared
    MapShared,
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
