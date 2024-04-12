// Copyright © 2022, Microsoft Corporation
// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Source: Original code from Cloud Hypervisor
//  - https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/devices/src/tpm.rs

use super::{TPM_SIZE, TPM_START};
use crate::vtpm::{vtpm_get_locked, vtpm_init, MsTpmSimulatorInterface};
use core::ops::Range;
use log::{debug, error};

#[derive(Debug, Clone, Copy)]
pub enum Error {
    CheckCaps,
    Init,
}
pub(crate) type Result<T> = core::result::Result<T, Error>;

#[allow(dead_code)]
enum LocStateFields {
    TpmEstablished,
    LocAssigned,
    ActiveLocality,
    Reserved,
    TpmRegValidSts,
}

enum LocStsFields {
    Granted,
    BeenSeized,
}

#[allow(dead_code)]
enum IntfIdFields {
    InterfaceType,
    InterfaceVersion,
    CapLocality,
    CapCRBIdleBypass,
    Reserved1,
    CapDataXferSizeSupport,
    CapFIFO,
    CapCRB,
    CapIFRes,
    InterfaceSelector,
    IntfSelLock,
    Reserved2,
    Rid,
}

#[allow(dead_code)]
enum IntfId2Fields {
    Vid,
    Did,
}

enum CtrlStsFields {
    TpmSts,
    TpmIdle,
}

enum CrbRegister {
    LocState(LocStateFields),
    LocSts(LocStsFields),
    IntfId(IntfIdFields),
    IntfId2(IntfId2Fields),
    CtrlSts(CtrlStsFields),
}

pub const TPM_CRB_BUFFER_MAX: usize = 3968; // 0x1_000 - 0x80

/* crb 32-bit registers */
const CRB_LOC_STATE: u32 = 0x0;
const CRB_LOC_CTRL: u32 = 0x08;
const CRB_LOC_CTRL_REQUEST_ACCESS: u32 = 1 << 0;
const CRB_LOC_CTRL_RELINQUISH: u32 = 1 << 1;
const CRB_LOC_CTRL_RESET_ESTABLISHMENT_BIT: u32 = 1 << 3;
const CRB_LOC_STS: u32 = 0x0C;
const CRB_INTF_ID: u32 = 0x30;
const CRB_INTF_ID2: u32 = 0x34;
const CRB_CTRL_REQ: u32 = 0x40;
const CRB_CTRL_REQ_CMD_READY: u32 = 1 << 0;
const CRB_CTRL_REQ_GO_IDLE: u32 = 1 << 1;
const CRB_CTRL_STS: u32 = 0x44;
const CRB_CTRL_CANCEL: u32 = 0x48;
const CRB_CANCEL_INVOKE: u32 = 1 << 0;
const CRB_CTRL_START: u32 = 0x4C;
const CRB_START_INVOKE: u32 = 1 << 0;
const CRB_CTRL_CMD_LADDR: u32 = 0x5C;
const CRB_CTRL_CMD_HADDR: u32 = 0x60;
const CRB_CTRL_RSP_SIZE: u32 = 0x64;
const CRB_CTRL_RSP_ADDR: u32 = 0x68;
const CRB_DATA_BUFFER: u32 = 0x80;

const TPM_CRB_NO_LOCALITY: u32 = 0xff;

const TPM_CRB_ADDR_BASE: u32 = TPM_START as u32;
const TPM_CRB_ADDR_SIZE: usize = TPM_SIZE as usize;

const TPM_CRB_R_MAX: usize = CRB_DATA_BUFFER as usize;

// CRB Register offset ranges
const CRB_LOC_STATE_RANGE: Range<usize> = 0x00..0x04;
const CRB_LOC_CTRL_RANGE: Range<usize> = 0x08..0x0C;
const CRB_LOC_STS_RANGE: Range<usize> = 0x0C..0x10;
const CRB_INTF_ID_1_RANGE: Range<usize> = 0x30..0x34;
const CRB_INTF_ID_2_RANGE: Range<usize> = 0x34..0x38;
const CRB_CTRL_REQ_RANGE: Range<usize> = 0x40..0x44;
const CRB_CTRL_STS_RANGE: Range<usize> = 0x44..0x48;
const CRB_CTRL_CANCEL_RANGE: Range<usize> = 0x48..0x4C;
const CRB_CTRL_START_RANGE: Range<usize> = 0x4C..0x50;
const CRB_CTRL_CMD_SIZE_REG_RANGE: Range<usize> = 0x58..0x5C;
const CRB_CTRL_CMD_LADDR_RANGE: Range<usize> = 0x5C..0x60;
const CRB_CTRL_CMD_HADDR_RANGE: Range<usize> = 0x60..0x64;
const CRB_CTRL_RSP_SIZE_RANGE: Range<usize> = 0x64..0x68;
const CRB_CTRL_RSP_ADDR_1_RANGE: Range<usize> = 0x68..0x6C;
const CRB_CTRL_RSP_ADDR_2_RANGE: Range<usize> = 0x6C..0x70;

// CRB Protocol details
const CRB_INTF_TYPE_CRB_ACTIVE: u32 = 0b1;
const CRB_INTF_VERSION_CRB: u32 = 0b1;
const CRB_INTF_CAP_LOCALITY_0_ONLY: u32 = 0b0;
const CRB_INTF_CAP_IDLE_FAST: u32 = 0b0;
const CRB_INTF_CAP_XFER_SIZE_64: u32 = 0b11;
const CRB_INTF_CAP_FIFO_NOT_SUPPORTED: u32 = 0b0;
const CRB_INTF_CAP_CRB_SUPPORTED: u32 = 0b1;
const CRB_INTF_IF_SELECTOR_CRB: u32 = 0b1;
const PCI_VENDOR_ID_IBM: u32 = 0x1014;
const CRB_CTRL_CMD_SIZE_REG: u32 = 0x58;
const CRB_CTRL_CMD_SIZE: usize = TPM_CRB_ADDR_SIZE - CRB_DATA_BUFFER as usize;

//Register Fields
// Field => (base, offset, length)
// base:   starting position of the register
// offset: lowest bit in the bit field numbered from 0
// length: length of the bit field
const fn get_crb_loc_state_field(f: LocStateFields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        LocStateFields::TpmEstablished => (0, 1),
        LocStateFields::LocAssigned => (1, 1),
        LocStateFields::ActiveLocality => (2, 3),
        LocStateFields::Reserved => (5, 2),
        LocStateFields::TpmRegValidSts => (7, 1),
    };

    (CRB_LOC_STATE, offset, len)
}

const fn get_crb_loc_sts_field(f: LocStsFields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        LocStsFields::Granted => (0, 1),
        LocStsFields::BeenSeized => (1, 1),
    };

    (CRB_LOC_STS, offset, len)
}

const fn get_crb_intf_id_field(f: IntfIdFields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        IntfIdFields::InterfaceType => (0, 4),
        IntfIdFields::InterfaceVersion => (4, 4),
        IntfIdFields::CapLocality => (8, 1),
        IntfIdFields::CapCRBIdleBypass => (9, 1),
        IntfIdFields::Reserved1 => (10, 1),
        IntfIdFields::CapDataXferSizeSupport => (11, 2),
        IntfIdFields::CapFIFO => (13, 1),
        IntfIdFields::CapCRB => (14, 1),
        IntfIdFields::CapIFRes => (15, 2),
        IntfIdFields::InterfaceSelector => (17, 2),
        IntfIdFields::IntfSelLock => (19, 1),
        IntfIdFields::Reserved2 => (20, 4),
        IntfIdFields::Rid => (24, 8),
    };

    (CRB_INTF_ID, offset, len)
}

const fn get_crb_ctrl_sts_field(f: CtrlStsFields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        CtrlStsFields::TpmSts => (0, 1),
        CtrlStsFields::TpmIdle => (1, 1),
    };

    (CRB_CTRL_STS, offset, len)
}

const fn get_crb_intf_id2_field(f: IntfId2Fields) -> (u32, u32, u32) {
    let (offset, len) = match f {
        IntfId2Fields::Vid => (0, 16),
        IntfId2Fields::Did => (16, 16),
    };

    (CRB_INTF_ID2, offset, len)
}

// Returns (register base, offset, len)
const fn get_field(reg: CrbRegister) -> (u32, u32, u32) {
    match reg {
        CrbRegister::LocState(f) => get_crb_loc_state_field(f),
        CrbRegister::LocSts(f) => get_crb_loc_sts_field(f),
        CrbRegister::IntfId(f) => get_crb_intf_id_field(f),
        CrbRegister::IntfId2(f) => get_crb_intf_id2_field(f),
        CrbRegister::CtrlSts(f) => get_crb_ctrl_sts_field(f),
    }
}

// Set a particular field in a Register
fn set_reg_field(regs: &mut [u32; TPM_CRB_R_MAX], reg: CrbRegister, value: u32) {
    let (base, offset, len) = get_field(reg);
    let mask = (!(0_u32) >> (32 - len)) << offset;
    regs[base as usize] = (regs[base as usize] & !mask) | ((value << offset) & mask);
}

// Get the value of a particular field in a Register
const fn get_reg_field(regs: &[u32; TPM_CRB_R_MAX], reg: CrbRegister) -> u32 {
    let (base, offset, len) = get_field(reg);
    let mask = (!(0_u32) >> (32 - len)) << offset;
    (regs[base as usize] & mask) >> offset
}

// Get the index of a Register based on offset
fn get_reg_idx(offset: usize) -> usize {
    match offset {
        o if CRB_LOC_STATE_RANGE.contains(&o) => CRB_LOC_STATE_RANGE.start,
        o if CRB_LOC_CTRL_RANGE.contains(&o) => CRB_LOC_CTRL_RANGE.start,
        o if CRB_LOC_STS_RANGE.contains(&o) => CRB_LOC_STS_RANGE.start,
        o if CRB_INTF_ID_1_RANGE.contains(&o) => CRB_INTF_ID_1_RANGE.start,
        o if CRB_INTF_ID_2_RANGE.contains(&o) => CRB_INTF_ID_2_RANGE.start,
        o if CRB_CTRL_REQ_RANGE.contains(&o) => CRB_CTRL_REQ_RANGE.start,
        o if CRB_CTRL_STS_RANGE.contains(&o) => CRB_CTRL_STS_RANGE.start,
        o if CRB_CTRL_CANCEL_RANGE.contains(&o) => CRB_CTRL_CANCEL_RANGE.start,
        o if CRB_CTRL_START_RANGE.contains(&o) => CRB_CTRL_START_RANGE.start,
        o if CRB_CTRL_CMD_SIZE_REG_RANGE.contains(&o) => CRB_CTRL_CMD_SIZE_REG_RANGE.start,
        o if CRB_CTRL_CMD_LADDR_RANGE.contains(&o) => CRB_CTRL_CMD_LADDR_RANGE.start,
        o if CRB_CTRL_CMD_HADDR_RANGE.contains(&o) => CRB_CTRL_CMD_HADDR_RANGE.start,
        o if CRB_CTRL_RSP_SIZE_RANGE.contains(&o) => CRB_CTRL_RSP_SIZE_RANGE.start,
        o if CRB_CTRL_RSP_ADDR_1_RANGE.contains(&o) => CRB_CTRL_RSP_ADDR_1_RANGE.start,
        o if CRB_CTRL_RSP_ADDR_2_RANGE.contains(&o) => CRB_CTRL_RSP_ADDR_2_RANGE.start,
        _ => TPM_CRB_R_MAX,
    }
}

fn locality_from_addr(addr: u32) -> u8 {
    (addr >> 12) as u8
}

#[derive(Debug)]
pub struct Tpm {
    regs: [u32; TPM_CRB_R_MAX],
    data_buff: [u8; TPM_CRB_BUFFER_MAX],
    data_buff_len: usize,
}

impl Tpm {
    pub const fn new() -> Self {
        Tpm {
            regs: [0; TPM_CRB_R_MAX],
            data_buff: [0; TPM_CRB_BUFFER_MAX],
            data_buff_len: 0,
        }
    }

    pub fn init(&mut self) -> Result<()> {
        self.reset()
    }

    pub fn mmio_read(&self, offset: u64, data: &mut [u8]) {
        let mut offset: u32 = offset as u32;
        let read_len: usize = data.len();

        if offset >= CRB_DATA_BUFFER
            && (offset + read_len as u32) < (CRB_DATA_BUFFER + self.data_buff.len() as u32)
        {
            // Read from Data Buffer
            let start: usize = (offset as usize) - (CRB_DATA_BUFFER as usize);
            let end: usize = start + read_len;
            data[..].clone_from_slice(&self.data_buff[start..end]);
        } else {
            offset &= 0xff;
            let reg_idx = get_reg_idx(offset as usize);
            if reg_idx == TPM_CRB_R_MAX {
                error!("Invalid tpm read: offset {:#X}", offset);
                return;
            }
            let reg_val = self.regs[reg_idx];
            let mut val = reg_val >> ((offset as usize - reg_idx) * 8);

            if offset == CRB_LOC_STATE
                && get_reg_field(
                    &self.regs,
                    CrbRegister::LocState(LocStateFields::TpmEstablished),
                ) != 0
            {
                val |= 0x1;
            }

            if data.len() <= 4 {
                data.clone_from_slice(val.to_ne_bytes()[0..read_len].as_ref());
            } else {
                error!(
                    "Invalid tpm read: offset {:#X}, data length {:?}",
                    offset,
                    data.len()
                );
            }
        }
        debug!(
            "MMIO Read: offset {:#X} len {:?} val = {:02X?}  ",
            offset,
            data.len(),
            data
        );
    }

    pub fn mmio_write(&mut self, offset: u64, data: &[u8]) {
        debug!(
            "MMIO Write: offset {:#X} len {:?} input data {:02X?}",
            offset,
            data.len(),
            data
        );
        let mut offset: u32 = offset as u32;
        if offset < CRB_DATA_BUFFER {
            offset &= 0xff;
        }
        let locality = locality_from_addr(offset) as u32;
        let mut write_len = data.len();

        if offset >= CRB_DATA_BUFFER
            && (offset + write_len as u32) < (CRB_DATA_BUFFER + self.data_buff.len() as u32)
        {
            let start: usize = (offset as usize) - (CRB_DATA_BUFFER as usize);
            if start == 0 {
                // If filling data_buff at index 0, reset length to 0
                self.data_buff_len = 0;
                self.data_buff.fill(0);
            }
            let end: usize = start + data.len();
            self.data_buff[start..end].clone_from_slice(data);
            self.data_buff_len += data.len();
        } else {
            // Ctrl Commands that take more than 4 bytes as input are not yet supported
            // CTRL_RSP_ADDR usually gets 8 byte write request. Last 4 bytes are zeros.
            if write_len > 4 && offset != CRB_CTRL_RSP_ADDR {
                error!(
                    "Invalid tpm write: offset {:#X}, data length {}",
                    offset,
                    data.len()
                );
            }

            if write_len > 4 {
                write_len = 4;
            }

            let mut input: [u8; 4] = [0; 4];
            input[..write_len].copy_from_slice(&data[..write_len]);
            let v = u32::from_le_bytes(input);

            match offset {
                CRB_CTRL_CMD_SIZE_REG => {
                    self.regs[CRB_CTRL_CMD_SIZE_REG as usize] = v;
                }
                CRB_CTRL_CMD_LADDR => {
                    self.regs[CRB_CTRL_CMD_LADDR as usize] = v;
                }
                CRB_CTRL_CMD_HADDR => {
                    self.regs[CRB_CTRL_CMD_HADDR as usize] = v;
                }
                CRB_CTRL_RSP_SIZE => {
                    self.regs[CRB_CTRL_RSP_SIZE as usize] = v;
                }
                CRB_CTRL_RSP_ADDR => {
                    self.regs[CRB_CTRL_RSP_ADDR as usize] = v;
                }
                CRB_CTRL_REQ => match v {
                    CRB_CTRL_REQ_CMD_READY => {
                        set_reg_field(
                            &mut self.regs,
                            CrbRegister::CtrlSts(CtrlStsFields::TpmIdle),
                            0,
                        );
                    }
                    CRB_CTRL_REQ_GO_IDLE => {
                        set_reg_field(
                            &mut self.regs,
                            CrbRegister::CtrlSts(CtrlStsFields::TpmIdle),
                            1,
                        );
                    }
                    _ => {
                        error!("Invalid value passed to CRTL_REQ register");
                    }
                },
                CRB_CTRL_CANCEL => {
                    if v == CRB_CANCEL_INVOKE
                        && (self.regs[CRB_CTRL_START as usize] & CRB_START_INVOKE != 0)
                    {
                        // TO: Implemente cancel interface
                    }
                }
                CRB_CTRL_START => {
                    if v == CRB_START_INVOKE
                        && ((self.regs[CRB_CTRL_START as usize] & CRB_START_INVOKE) == 0)
                        && self.get_active_locality() == locality
                    {
                        self.regs[CRB_CTRL_START as usize] |= CRB_START_INVOKE;

                        let backend = vtpm_get_locked();
                        let mut output_len = self.data_buff_len;
                        if backend
                            .send_tpm_command(&mut self.data_buff, &mut output_len, 0)
                            .is_ok()
                        {
                            self.request_completed(true);
                        } else {
                            self.request_completed(false);
                        }
                    }
                }
                CRB_LOC_CTRL => match v {
                    CRB_LOC_CTRL_RESET_ESTABLISHMENT_BIT => {}
                    CRB_LOC_CTRL_RELINQUISH => {
                        set_reg_field(
                            &mut self.regs,
                            CrbRegister::LocState(LocStateFields::LocAssigned),
                            0,
                        );
                        set_reg_field(
                            &mut self.regs,
                            CrbRegister::LocSts(LocStsFields::Granted),
                            0,
                        );
                    }
                    CRB_LOC_CTRL_REQUEST_ACCESS => {
                        set_reg_field(
                            &mut self.regs,
                            CrbRegister::LocSts(LocStsFields::Granted),
                            1,
                        );
                        set_reg_field(
                            &mut self.regs,
                            CrbRegister::LocSts(LocStsFields::BeenSeized),
                            0,
                        );
                        set_reg_field(
                            &mut self.regs,
                            CrbRegister::LocState(LocStateFields::LocAssigned),
                            1,
                        );
                    }
                    _ => {
                        error!("Invalid value to write in CRB_LOC_CTRL {:#X} ", v);
                    }
                },
                _ => {
                    error!(
                        "Invalid tpm write: offset {:#X}, data length {:?}",
                        offset,
                        data.len()
                    );
                }
            }
        }
    }

    fn get_active_locality(&mut self) -> u32 {
        if get_reg_field(
            &self.regs,
            CrbRegister::LocState(LocStateFields::LocAssigned),
        ) == 0
        {
            return TPM_CRB_NO_LOCALITY;
        }
        get_reg_field(
            &self.regs,
            CrbRegister::LocState(LocStateFields::ActiveLocality),
        )
    }

    fn request_completed(&mut self, success: bool) {
        self.regs[CRB_CTRL_START as usize] = !CRB_START_INVOKE;
        if !success {
            set_reg_field(
                &mut self.regs,
                CrbRegister::CtrlSts(CtrlStsFields::TpmSts),
                1,
            );
        }
    }

    fn reset(&mut self) -> Result<()> {
        // let cur_buff_size = self.emulator.get_buffer_size();
        self.regs = [0; TPM_CRB_R_MAX];
        set_reg_field(
            &mut self.regs,
            CrbRegister::LocState(LocStateFields::TpmRegValidSts),
            1,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::CtrlSts(CtrlStsFields::TpmIdle),
            1,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::InterfaceType),
            CRB_INTF_TYPE_CRB_ACTIVE,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::InterfaceVersion),
            CRB_INTF_VERSION_CRB,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapLocality),
            CRB_INTF_CAP_LOCALITY_0_ONLY,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapCRBIdleBypass),
            CRB_INTF_CAP_IDLE_FAST,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapDataXferSizeSupport),
            CRB_INTF_CAP_XFER_SIZE_64,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapFIFO),
            CRB_INTF_CAP_FIFO_NOT_SUPPORTED,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::CapCRB),
            CRB_INTF_CAP_CRB_SUPPORTED,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::InterfaceSelector),
            CRB_INTF_IF_SELECTOR_CRB,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId(IntfIdFields::Rid),
            0b0000,
        );
        set_reg_field(
            &mut self.regs,
            CrbRegister::IntfId2(IntfId2Fields::Vid),
            PCI_VENDOR_ID_IBM,
        );

        self.regs[CRB_CTRL_CMD_SIZE_REG as usize] = CRB_CTRL_CMD_SIZE as u32;
        self.regs[CRB_CTRL_CMD_LADDR as usize] = TPM_CRB_ADDR_BASE + CRB_DATA_BUFFER;
        self.regs[CRB_CTRL_RSP_SIZE as usize] = CRB_CTRL_CMD_SIZE as u32;
        self.regs[CRB_CTRL_RSP_ADDR as usize] = TPM_CRB_ADDR_BASE + CRB_DATA_BUFFER;

        if let Err(_e) = vtpm_init() {
            return Err(Error::Init);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_get_reg_field() {
        let mut regs: [u32; TPM_CRB_R_MAX] = [0; TPM_CRB_R_MAX];
        set_reg_field(&mut regs, CrbRegister::IntfId(IntfIdFields::Rid), 0xAC);
        assert_eq!(
            get_reg_field(&regs, CrbRegister::IntfId(IntfIdFields::Rid)),
            0xAC,
            concat!("Test: ", stringify!(set_get_reg_field))
        );
    }
}
