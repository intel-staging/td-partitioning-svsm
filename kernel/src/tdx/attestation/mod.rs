// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Jiaqi Gao <jiaqi.gao@intel.com>

mod qgs;
mod tdx_report;

use super::{error::TdxError, tdcall::tdvmcall_get_quote};
use crate::{
    address::{Address, VirtAddr},
    error::SvsmError,
    mm::{
        alloc::{allocate_pages, free_page},
        virt_to_phys, PAGE_SIZE,
    },
    tdx::utils::td_convert_kernel_pages,
};
use core::{mem::size_of, ops::Add};
use qgs::{qgs_get_quote_message, QgsMessageGetQuoteRsp};
use tdx_report::{get_tdx_report, TDX_REPORT_SIZE};

const GET_QUOTE_VERSION: u64 = 1;
// TDX GetQuote status codes
const GET_QUOTE_STATUS_SUCCESS: u64 = 0;
const GET_QUOTE_STATUS_IN_FLIGHT: u64 = 0xffffffffffffffff;

const GET_QUOTE_BUF_SIZE: usize = PAGE_SIZE * 2;
const GET_QUOTE_BUF_SIZE_ORDER: usize = 1;

#[repr(C)]
struct TdxGetQuoteHeader {
    version: u64,
    status: u64,
    in_len: u32,
    out_len: u32,
}

impl TdxGetQuoteHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

struct TdxGetQuoteBuf<'a> {
    buffer: &'a mut [u8],
}

impl<'a> TdxGetQuoteBuf<'a> {
    fn new(buffer: &'a mut [u8], tdx_report: &[u8]) -> Result<Self, SvsmError> {
        let header_size = size_of::<TdxGetQuoteHeader>();
        let qgs_msg_offset = header_size + size_of::<u32>();
        let qgs_message_length = qgs_get_quote_message(tdx_report, &mut buffer[qgs_msg_offset..])?;
        let in_len = size_of::<u32>() as u32 + qgs_message_length;

        let header = TdxGetQuoteHeader {
            version: GET_QUOTE_VERSION,
            status: GET_QUOTE_STATUS_SUCCESS,
            in_len,
            out_len: 0,
        };
        buffer[..header_size].copy_from_slice(header.as_bytes());
        buffer[header_size..qgs_msg_offset].copy_from_slice(&qgs_message_length.to_be_bytes());

        Ok(Self { buffer })
    }

    fn status_code(&self) -> u64 {
        u64::from_le_bytes(self.buffer[8..16].try_into().unwrap())
    }

    fn reset_status_code(&mut self) {
        self.buffer[8..16].fill(0);
    }

    fn output_length(&self) -> u32 {
        u32::from_le_bytes(self.buffer[20..24].try_into().unwrap())
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.buffer
    }

    pub fn message(&self) -> &[u8] {
        &self.buffer[28..]
    }
}

pub fn quote_generation(additional_data: &[u8], output: &mut [u8]) -> Result<usize, SvsmError> {
    // Get the TDX report via TDCALL
    let mut tdx_report = [0u8; TDX_REPORT_SIZE];
    get_tdx_report(additional_data, &mut tdx_report)?;

    // Allocate pages for getting quote from host and set them as shared.
    let pages = set_get_quote_buf()?;

    // Setup get quote buffer
    let slice = unsafe { core::slice::from_raw_parts_mut(pages.as_mut_ptr(), GET_QUOTE_BUF_SIZE) };
    let mut get_quote_buf = TdxGetQuoteBuf::new(slice, &tdx_report)?;

    // Get quote from host VMM via VMCALL
    get_quote_from_host(&mut get_quote_buf)?;

    // Then check the returned status code and the output length from host VMM
    if get_quote_buf.status_code() != 0 {
        return Err(SvsmError::Tdx(TdxError::Attestation));
    }

    if get_quote_buf.output_length() < 4 {
        return Err(SvsmError::Tdx(TdxError::Attestation));
    }

    // Finally, parse the QGS message and copy the quote out.
    let quote_response = QgsMessageGetQuoteRsp::new_checked(get_quote_buf.message())?;
    if output.len() < quote_response.quote().len() {
        return Err(SvsmError::Tdx(TdxError::Attestation));
    }
    output[..quote_response.quote().len()].copy_from_slice(quote_response.quote());

    // Free the pages used for getting quote and convert them to private.
    free_get_quote_buf(pages)?;

    Ok(quote_response.quote().len())
}

fn set_get_quote_buf() -> Result<VirtAddr, SvsmError> {
    let pages = allocate_pages(GET_QUOTE_BUF_SIZE_ORDER)?;
    let paddr = virt_to_phys(pages);

    if td_convert_kernel_pages(paddr, paddr.add(GET_QUOTE_BUF_SIZE), true)
        .map_err(SvsmError::Tdx)?
        != GET_QUOTE_BUF_SIZE
    {
        return Err(SvsmError::Tdx(TdxError::Attestation));
    }

    Ok(pages)
}

fn free_get_quote_buf(pages: VirtAddr) -> Result<(), SvsmError> {
    let paddr = virt_to_phys(pages);

    if td_convert_kernel_pages(paddr, paddr.add(GET_QUOTE_BUF_SIZE), false)
        .map_err(SvsmError::Tdx)?
        != GET_QUOTE_BUF_SIZE
    {
        return Err(SvsmError::Tdx(TdxError::Attestation));
    }

    free_page(pages);

    Ok(())
}

fn get_quote_from_host(request: &mut TdxGetQuoteBuf<'_>) -> Result<(), SvsmError> {
    let paddr =
        virt_to_phys(VirtAddr::new(request.as_bytes_mut().as_mut_ptr() as usize)).bits() as u64;
    while tdvmcall_get_quote(paddr, request.as_bytes_mut().len() as u64).is_ok() {
        if request.status_code() == GET_QUOTE_STATUS_SUCCESS {
            return Ok(());
        } else if request.status_code() != GET_QUOTE_STATUS_IN_FLIGHT {
            return Err(SvsmError::Tdx(TdxError::Attestation));
        }
        request.reset_status_code();
    }

    Err(SvsmError::Tdx(TdxError::Attestation))
}
