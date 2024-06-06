// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Jiaqi Gao <jiaqi.gao@intel.com>

use crate::{
    address::Address,
    error::SvsmError,
    mm::{
        alloc::{allocate_zeroed_page, free_page},
        virt_to_phys,
    },
    tdx::{
        error::TdxError,
        tdcall::{td_call, TdcallArgs, TDCALL_TDREPORT, TDVMCALL_STATUS_SUCCESS},
    },
};

pub const TDX_REPORT_SIZE: usize = 1024;
pub const TDX_REPORT_DATA_SIZE: usize = 64;

pub fn get_tdx_report(additional_data: &[u8], output: &mut [u8]) -> Result<(), SvsmError> {
    if additional_data.len() > TDX_REPORT_DATA_SIZE || output.len() != TDX_REPORT_SIZE {
        return Err(SvsmError::Tdx(TdxError::GetReport));
    }

    let vaddr = allocate_zeroed_page()?;
    let report_buff = unsafe {
        core::slice::from_raw_parts_mut(vaddr.as_mut_ptr(), TDX_REPORT_SIZE + TDX_REPORT_DATA_SIZE)
    };
    report_buff[TDX_REPORT_SIZE..TDX_REPORT_SIZE + additional_data.len()]
        .copy_from_slice(additional_data);

    let paddr = virt_to_phys(vaddr).bits() as u64;
    let mut args = TdcallArgs {
        rax: TDCALL_TDREPORT,
        rcx: paddr,
        rdx: paddr
            .checked_add(TDX_REPORT_SIZE as u64)
            .ok_or(SvsmError::Tdx(TdxError::GetReport))?,
        ..Default::default()
    };

    let ret = td_call(&mut args);
    if ret != TDVMCALL_STATUS_SUCCESS {
        return Err(SvsmError::Tdx(TdxError::GetReport));
    }

    output.copy_from_slice(&report_buff[..TDX_REPORT_SIZE]);
    free_page(vaddr);

    Ok(())
}
