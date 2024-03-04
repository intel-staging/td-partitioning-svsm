// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::error::TdxError;
use crate::address::GuestPhysAddr;
use crate::mm::address_space::is_kernel_phys_addr_valid;
use crate::mm::guestmem::gpa_is_shared;
use crate::mm::memory::is_guest_phys_addr_valid;

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq)]
enum AddrSize {
    ZeroByte,
    OneByte,
    TwoBytes,
    FourBytes = 4,
    EightBytes = 8,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum IoDirection {
    Read,
    Write,
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
struct IoOperation {
    io_dir: IoDirection,
    data: u64,
}

impl IoOperation {
    fn new(io_dir: IoDirection) -> Self {
        IoOperation { io_dir, data: 0 }
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
