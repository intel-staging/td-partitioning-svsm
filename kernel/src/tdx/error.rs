// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ErrExcp {
    GP(u32),
}

#[derive(Clone, Copy, Debug)]
pub enum TdxError {
    // Require to inject exception to Guest
    InjectExcp(ErrExcp),
    // Invalid vm id
    InvalidVmId(u64),
    // Tdp guest is not supported
    TdpNotSupport,
    // Vm read related error
    VmRD(u64),
    // Vp write related error
    VpWR(u64, u64),
}
