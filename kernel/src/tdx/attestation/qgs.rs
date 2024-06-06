// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Jiaqi Gao <jiaqi.gao@intel.com>

use crate::{error::SvsmError, tdx::error::TdxError};

use core::mem::size_of;

use super::tdx_report::TDX_REPORT_SIZE;

const QGS_MESSAGE_MAJOR_VERSION: u16 = 1;
const QGS_MESSAGE_MINOR_VERSION: u16 = 0;

#[repr(C)]
#[derive(Debug, Default)]
pub struct QgsMessageHeader {
    major_version: u16,
    minor_version: u16,
    message_type: u32,
    message_size: u32,
    result_code: u32,
}

impl QgsMessageHeader {
    fn read_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }

        let mut header = QgsMessageHeader::default();
        header
            .as_mut_bytes()
            .copy_from_slice(&bytes[..size_of::<Self>()]);

        Some(header)
    }

    fn as_mut_bytes(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self as *mut Self as *mut u8, size_of::<Self>()) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

#[repr(u32)]
#[derive(Debug, PartialEq, Eq)]
pub enum QgsMessageType {
    GetQuoteReq = 0,
    GetQuoteRsp = 1,
    GetCollateralReq = 2,
    GetCollateralRsp = 3,
    GetPlatformInfoReq = 4,
    GetPlatformInfoRsp = 5,
    Unknown,
}

impl From<u32> for QgsMessageType {
    fn from(value: u32) -> Self {
        match value {
            0 => QgsMessageType::GetQuoteReq,
            1 => QgsMessageType::GetQuoteRsp,
            2 => QgsMessageType::GetCollateralReq,
            3 => QgsMessageType::GetCollateralRsp,
            4 => QgsMessageType::GetPlatformInfoReq,
            5 => QgsMessageType::GetPlatformInfoRsp,
            _ => QgsMessageType::Unknown,
        }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum QgsMessageResultCode {
    Success = 0,
    Unexpected = 0x0001_2001,
    OutOfMemory = 0x0001_2002,
    InvalidParamter = 0x0001_2003,
    InvalidVersion = 0x0001_2004,
    InvalidType = 0x0001_2005,
    InvalidSize = 0x0001_2006,
    InvalidCode = 0x0001_2007,
    Unknown,
}

impl From<u32> for QgsMessageResultCode {
    fn from(value: u32) -> Self {
        match value {
            0 => QgsMessageResultCode::Success,
            0x0001_2001 => QgsMessageResultCode::Unexpected,
            0x0001_2002 => QgsMessageResultCode::OutOfMemory,
            0x0001_2003 => QgsMessageResultCode::InvalidParamter,
            0x0001_2004 => QgsMessageResultCode::InvalidVersion,
            0x0001_2005 => QgsMessageResultCode::InvalidType,
            0x0001_2006 => QgsMessageResultCode::InvalidSize,
            0x0001_2007 => QgsMessageResultCode::InvalidCode,
            _ => QgsMessageResultCode::Unknown,
        }
    }
}

#[repr(C)]
struct QgsMessageGetQuoteReqBody {
    report_size: u32,
    id_list_size: u32,
}

impl QgsMessageGetQuoteReqBody {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

pub fn qgs_get_quote_message(report: &[u8], message: &mut [u8]) -> Result<u32, SvsmError> {
    if report.len() != TDX_REPORT_SIZE {
        return Err(SvsmError::Tdx(TdxError::Attestation));
    }

    let header_size = size_of::<QgsMessageHeader>();
    let body_size = size_of::<QgsMessageGetQuoteReqBody>();
    let message_size = header_size + body_size + report.len();

    // `message` must be large enough to hold the whole message
    if message.len() < message_size {
        return Err(SvsmError::Tdx(TdxError::Attestation));
    }

    // Write the QGS message header
    let header = QgsMessageHeader {
        major_version: QGS_MESSAGE_MAJOR_VERSION,
        minor_version: QGS_MESSAGE_MINOR_VERSION,
        message_type: QgsMessageType::GetQuoteReq as u32,
        message_size: message_size as u32,
        result_code: QgsMessageResultCode::Success as u32,
    };
    message[..header_size].copy_from_slice(header.as_bytes());

    // Write the report size and the id list size
    let body = QgsMessageGetQuoteReqBody {
        report_size: report.len() as u32,
        id_list_size: 0,
    };
    message[header_size..header_size + body_size].copy_from_slice(body.as_bytes());

    // Copy the report into the message buffer
    let message = &mut message[header_size + body_size..];
    message[..report.len()].copy_from_slice(report);

    Ok(header.message_size)
}

#[allow(unused)]
pub struct QgsMessageGetQuoteRsp<'a> {
    selected_id: &'a [u8],
    quote: &'a [u8],
}

impl<'a> QgsMessageGetQuoteRsp<'a> {
    pub fn new_checked(message: &'a [u8]) -> Result<Self, SvsmError> {
        if message.len() < size_of::<QgsMessageHeader>() + size_of::<u32>() * 2 {
            return Err(SvsmError::Tdx(TdxError::Attestation));
        }

        let header = QgsMessageHeader::read_from_bytes(message)
            .ok_or(SvsmError::Tdx(TdxError::Attestation))?;

        if header.major_version != QGS_MESSAGE_MAJOR_VERSION
            || header.message_type != QgsMessageType::GetQuoteRsp as u32
            || header.result_code != QgsMessageResultCode::Success as u32
        {
            return Err(SvsmError::Tdx(TdxError::Attestation));
        }

        let selected_id_size = Self::selected_id_size(message) as usize;
        let selected_id_offset = size_of::<QgsMessageHeader>() + size_of::<u32>() * 2;
        let quote_size = Self::quote_size(message) as usize;
        let quote_offset = size_of::<QgsMessageHeader>() + size_of::<u32>() * 2 + selected_id_size;

        Ok(Self {
            selected_id: &message[selected_id_offset..selected_id_offset + selected_id_size],
            quote: &message[quote_offset..quote_offset + quote_size],
        })
    }

    pub fn quote(&self) -> &[u8] {
        self.quote
    }

    #[allow(unused)]
    pub fn selected_id(&self) -> &[u8] {
        self.selected_id
    }

    fn selected_id_size(message: &[u8]) -> u32 {
        u32::from_le_bytes(message[16..20].try_into().unwrap())
    }

    fn quote_size(message: &[u8]) -> u32 {
        u32::from_le_bytes(message[20..24].try_into().unwrap())
    }
}
