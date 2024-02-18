// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

#[derive(Clone, Copy, Debug)]
pub enum TdxError {
    // Invalid Vm Id
    InvalidVmId(u64),
    // Tdp guest is not supported
    TdpNotSupport,
    // Vm read related error
    VmRD(u64),
}
