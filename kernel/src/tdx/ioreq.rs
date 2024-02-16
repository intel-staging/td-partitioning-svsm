// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::error::TdxError;
use super::gmem::{copy_from_gpa, copy_to_gpa};
use super::instr_emul::InstrEmul;
use super::percpu::{this_vcpu, this_vcpu_mut};
use super::tdcall::{tdvmcall_mmio_read, tdvmcall_mmio_write};
use super::tdp::this_tdp;
use super::utils::TdpVmId;
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

struct IoInstrEmul<'a>(InstrEmul<'a>);

impl IoEmul for IoInstrEmul<'_> {
    fn emulate_read(&mut self, io_op: &mut IoOperation) -> Result<(), TdxError> {
        self.0.emulate_instr(io_op)
    }

    fn emulate_write(&mut self, io_op: &mut IoOperation) -> Result<(), TdxError> {
        self.0.emulate_instr(io_op)
    }

    // Get the IO operation size
    fn get_opsize(&self) -> AddrSize {
        self.0.get_opsize()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum IoType {
    Mmio {
        addr: GuestPhysAddr,
        instr_len: usize,
    },
}

pub struct IoReq {
    vm_id: TdpVmId,
    io_type: IoType,
    io_op: IoOperation,
}

impl IoReq {
    pub fn new(vm_id: TdpVmId, io_type: IoType, io_dir: IoDirection) -> IoReq {
        IoReq {
            vm_id,
            io_type,
            io_op: IoOperation::new(io_dir),
        }
    }

    fn emulate_mmio(&mut self, gpa: GuestPhysAddr, mut emul: impl IoEmul) -> Result<(), TdxError> {
        // Check if the requested GPA is private address. Not allow TDP guest accessing its private
        // memory or SVSM's memory through an MMIO request.
        if !gpa_is_shared(gpa)
            && (is_guest_phys_addr_valid(gpa) || is_kernel_phys_addr_valid(gpa.to_host_phys_addr()))
        {
            return Err(TdxError::IoEmul(self.io_type));
        }

        let size = emul.get_opsize();
        let addr = u64::from(gpa);
        let io_op = &mut self.io_op;
        let (vlapic_mmio_start, vlapic_mmio_end) = this_vcpu(self.vm_id).get_vlapic().mmio_range();
        let (vioapic_mmio_start, vioapic_mmio_end) =
            this_tdp(self.vm_id).get_vioapic().get_mmio_range();
        if io_op.is_read() {
            io_op.data = match addr {
                // MMIO belongs to virtual lapic is emulated by SVSM.
                v if (v >= vlapic_mmio_start && (v + size as u64) < vlapic_mmio_end) => {
                    this_vcpu(self.vm_id)
                        .get_vlapic()
                        .read_reg((addr - vlapic_mmio_start) as u32)? as u64
                }
                //MMIO belonging to virtual IOAPIC
                v if v >= vioapic_mmio_start && (v + size as u64) < vioapic_mmio_end => {
                    this_tdp(self.vm_id)
                        .get_vioapic()
                        .mmio_read(v, size as u32)? as u64
                }
                // Other MMIO are emulated by host, so send MMIO tdvmcall
                // to host to emulate.
                _ => match size {
                    AddrSize::OneByte => tdvmcall_mmio_read::<u8>(addr as usize) as u64,
                    AddrSize::TwoBytes => tdvmcall_mmio_read::<u16>(addr as usize) as u64,
                    AddrSize::FourBytes => tdvmcall_mmio_read::<u32>(addr as usize) as u64,
                    AddrSize::EightBytes => tdvmcall_mmio_read::<u64>(addr as usize),
                    _ => return Err(TdxError::IoEmul(self.io_type)),
                },
            };
            emul.emulate_read(io_op)?;
        } else {
            emul.emulate_write(io_op)?;
            match addr {
                // MMIO belongs to virtual lapic is emulated by SVSM.
                v if (v >= vlapic_mmio_start && (v + size as u64) < vlapic_mmio_end) => {
                    this_vcpu_mut(self.vm_id)
                        .get_vlapic_mut()
                        .write_reg((addr - vlapic_mmio_start) as u32, io_op.data)?
                }
                //MMIO belonging to virtual IOAPIC
                v if v >= vioapic_mmio_start && (v + size as u64) < vioapic_mmio_end => this_tdp(
                    self.vm_id,
                )
                .get_vioapic()
                .mmio_write(v, io_op.data as u32, size as u32)?,
                // Other MMIO are emulated by host, so send MMIO tdvmcall
                // to host to emulate.
                _ => match size {
                    AddrSize::OneByte => {
                        tdvmcall_mmio_write::<u8>(addr as *const u8, io_op.data as u8)
                    }
                    AddrSize::TwoBytes => {
                        tdvmcall_mmio_write::<u16>(addr as *const u16, io_op.data as u16)
                    }
                    AddrSize::FourBytes => {
                        tdvmcall_mmio_write::<u32>(addr as *const u32, io_op.data as u32)
                    }
                    AddrSize::EightBytes => {
                        tdvmcall_mmio_write::<u64>(addr as *const u64, io_op.data)
                    }
                    _ => return Err(TdxError::IoEmul(self.io_type)),
                },
            }
        }
        Ok(())
    }

    pub fn emulate(&mut self) -> Result<(), TdxError> {
        match self.io_type {
            IoType::Mmio { addr, instr_len } => self.emulate_mmio(
                addr,
                IoInstrEmul(InstrEmul::decode_instr(
                    this_vcpu_mut(self.vm_id).get_ctx_mut(),
                    instr_len,
                )?),
            ),
        }
    }

    pub fn need_retry(&self) -> bool {
        self.io_op.retry
    }
}
