// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Jason CJ Chen <jason.cj.chen@intel.com>

pub mod error;

mod gctx;
mod gmem;
mod instr_emul;
mod interrupts;
mod ioreq;
mod measurement;
mod msr_bitmap;
mod opcode;
mod percpu;
mod service;
mod sirte;
mod tdcall;
mod tdp;
mod tdvf;
mod utils;
mod vcpu;
mod vcpu_comm;
mod vcpuid;
mod vcr;
mod vioapic;
mod virq;
mod vlapic;
mod vmcs;
mod vmcs_lib;
mod vmexit;
mod vmsr;

pub use measurement::tdx_tpm_measurement_init;
pub use percpu::{run_tdpvp, TdPerCpu};
pub use tdcall::{
    td_accept_memory, td_shared_mask, tdcall_get_ve_info, tdvmcall_cpuid, tdvmcall_halt,
    tdvmcall_io_read_16, tdvmcall_io_read_8, tdvmcall_io_write_16, tdvmcall_io_write_8,
    tdvmcall_rdmsr, tdvmcall_wrmsr, TdVmcallError,
};
