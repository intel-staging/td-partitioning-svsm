// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

mod tdcall;

pub use tdcall::{
    td_accept_memory, td_shared_mask, tdcall_get_ve_info, tdvmcall_cpuid, tdvmcall_halt,
    tdvmcall_io_read_16, tdvmcall_io_read_8, tdvmcall_io_write_16, tdvmcall_io_write_8,
    tdvmcall_rdmsr, tdvmcall_wrmsr, TdVmcallError,
};
