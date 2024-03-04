// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::error::TdxError;
use super::gmem::{copy_from_gpa, copy_to_gpa};
use crate::address::GuestPhysAddr;
use crate::mm::address_space::is_kernel_phys_addr_valid;
use crate::mm::guestmem::gpa_is_shared;
use crate::mm::memory::is_guest_phys_addr_valid;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AddrSize {
    ZeroByte,
    OneByte,
    TwoBytes,
    FourBytes = 4,
    EightBytes = 8,
}

pub fn copy_from_gpa_addrsize(gpa: GuestPhysAddr, size: AddrSize) -> Result<u64, TdxError> {
    match size {
        AddrSize::ZeroByte => Ok(0),
        AddrSize::OneByte => Ok(copy_from_gpa::<u8>(gpa)? as u64),
        AddrSize::TwoBytes => Ok(copy_from_gpa::<u16>(gpa)? as u64),
        AddrSize::FourBytes => Ok(copy_from_gpa::<u32>(gpa)? as u64),
        AddrSize::EightBytes => Ok(copy_from_gpa::<u64>(gpa)?),
    }
}

pub fn copy_to_gpa_addrsize(gpa: GuestPhysAddr, size: AddrSize, val: u64) -> Result<(), TdxError> {
    match size {
        AddrSize::ZeroByte => Ok(()),
        AddrSize::OneByte => copy_to_gpa::<u8>(gpa, val as u8),
        AddrSize::TwoBytes => copy_to_gpa::<u16>(gpa, val as u16),
        AddrSize::FourBytes => copy_to_gpa::<u32>(gpa, val as u32),
        AddrSize::EightBytes => copy_to_gpa::<u64>(gpa, val),
    }
}

impl AddrSize {
    pub fn mask(&self) -> u64 {
        match self {
            AddrSize::ZeroByte => 0,
            AddrSize::OneByte => (1 << 8) - 1,
            AddrSize::TwoBytes => (1 << 16) - 1,
            AddrSize::FourBytes => (1 << 32) - 1,
            AddrSize::EightBytes => u64::MAX,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum IoDirection {
    Read,
    Write,
}

#[derive(Copy, Clone, Debug)]
pub struct IoOperation {
    io_dir: IoDirection,
    data: u64,
    retry: bool,
}

impl IoOperation {
    fn new(io_dir: IoDirection) -> Self {
        IoOperation {
            io_dir,
            data: 0,
            retry: false,
        }
    }

    pub fn is_read(&self) -> bool {
        self.io_dir == IoDirection::Read
    }

    pub fn get_read_data(&self) -> Option<u64> {
        if self.is_read() {
            Some(self.data)
        } else {
            None
        }
    }

    pub fn set_write_data(&mut self, val: u64) {
        if !self.is_read() {
            self.data = val;
        }
    }

    pub fn set_retry(&mut self) {
        self.retry = true;
    }
}

trait IoEmul {
    // Write the read data back
    fn emulate_read(&mut self, _io_op: &mut IoOperation) -> Result<(), TdxError> {
        Err(TdxError::IoEmulNotSupport)
    }

    // Get the write data
    fn emulate_write(&mut self, _io_op: &mut IoOperation) -> Result<(), TdxError> {
        Err(TdxError::IoEmulNotSupport)
    }

    // Get the IO operation size
    fn get_opsize(&self) -> AddrSize {
        AddrSize::ZeroByte
    }
}

struct IoInstrEmul;

impl IoEmul for IoInstrEmul {
    //TODO: implement instruction emulation support
}

#[derive(Clone, Copy, Debug)]
pub enum IoType {
    Mmio {
        addr: GuestPhysAddr,
        instr_len: usize,
    },
}

#[allow(dead_code)]
pub struct IoReq {
    io_type: IoType,
    io_op: IoOperation,
}

impl IoReq {
    pub fn new(io_type: IoType, io_dir: IoDirection) -> IoReq {
        IoReq {
            io_type,
            io_op: IoOperation::new(io_dir),
        }
    }

    fn emulate_mmio(&mut self, gpa: GuestPhysAddr, _emul: impl IoEmul) -> Result<(), TdxError> {
        // Check if the requested GPA is private address. Not allow TDP guest accessing its private
        // memory or SVSM's memory through an MMIO request.
        if !gpa_is_shared(gpa)
            && (is_guest_phys_addr_valid(gpa) || is_kernel_phys_addr_valid(gpa.to_host_phys_addr()))
        {
            return Err(TdxError::IoEmul(self.io_type));
        }

        //TODO: emulate MMIO
        Err(TdxError::IoEmulNotSupport)
    }

    pub fn emulate(&mut self) -> Result<(), TdxError> {
        match self.io_type {
            IoType::Mmio { addr, instr_len: _ } => self.emulate_mmio(addr, IoInstrEmul),
        }
    }
}
