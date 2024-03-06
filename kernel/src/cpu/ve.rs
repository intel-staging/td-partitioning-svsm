// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023-2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::extable::handle_exception_table;
use super::idt::common::X86ExceptionContext;
use crate::tdx::{
    tdcall_get_ve_info, tdvmcall_cpuid, tdvmcall_rdmsr, tdvmcall_wrmsr, TdVmcallError,
};

const VMX_EXIT_REASON_CPUID: u32 = 10;
const VMX_EXIT_REASON_RDMSR: u32 = 31;
const VMX_EXIT_REASON_WRMSR: u32 = 32;

pub fn handle_virtualization_exception(ctx: &mut X86ExceptionContext) {
    let veinfo = tdcall_get_ve_info().expect("Failed to get #VE info");

    match veinfo.exit_reason {
        VMX_EXIT_REASON_CPUID => {
            let leaf = ctx.regs.rax as u32;
            let subleaf = ctx.regs.rcx as u32;
            let cpuid = tdvmcall_cpuid(leaf, subleaf);

            ctx.regs.rax = cpuid.eax as usize;
            ctx.regs.rbx = cpuid.ebx as usize;
            ctx.regs.rcx = cpuid.ecx as usize;
            ctx.regs.rdx = cpuid.edx as usize;
        }
        VMX_EXIT_REASON_RDMSR => {
            let msr_val = match tdvmcall_rdmsr(ctx.regs.rcx as u32) {
                Ok(v) => v,
                Err(TdVmcallError::VmcallOperandInvalid) => {
                    let rip = ctx.frame.rip;
                    if !handle_exception_table(ctx) {
                        panic!("Unhandled RDMSR #VE exception at RIP {:#018x}", rip);
                    }
                    return;
                }
                Err(e) => panic!("Unhandled tdvmcall_rdmsr error: {:?}", e),
            };

            ctx.regs.rax = (msr_val as u32).try_into().unwrap();
            ctx.regs.rdx = (msr_val >> 32).try_into().unwrap();
        }
        VMX_EXIT_REASON_WRMSR => {
            let msr_val = u64::from(ctx.regs.rax as u32) | ((ctx.regs.rdx as u64) << 32);

            if let Err(e) = tdvmcall_wrmsr(ctx.regs.rcx as u32, msr_val) {
                match e {
                    TdVmcallError::VmcallOperandInvalid => {
                        let rip = ctx.frame.rip;
                        if !handle_exception_table(ctx) {
                            panic!("Unhandled WRMSR #VE exception at RIP {:#018x}", rip);
                        }
                    }
                    e => panic!("Unhandled tdvmcall_wrmsr error: {:?}", e),
                }
            }
        }
        _ => {
            let rip = ctx.frame.rip;

            panic!(
                "Unhandled #VE exception RIP {:#018x} exit_reason: {:#018x}",
                rip, veinfo.exit_reason
            );
        }
    }

    ctx.frame.rip += veinfo.exit_instruction_length as usize;
}
