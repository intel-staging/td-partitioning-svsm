// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use bitflags::bitflags;

#[derive(Clone, Copy, Debug)]
pub enum OpCodeError {
    OpCode(u8),
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct OpFlags: u16 {
        const IMM           = 1 << 0;
        const IMM8          = 1 << 1;
        const MOFFSET       = 1 << 2;
        const NO_MODRM      = 1 << 3;
        const BYTE_OP       = 1 << 4;
        const WORD_OP       = 1 << 5;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub enum OpType {
    #[default]
    UnSupported,
    And,
    BitTest,
    Cmp,
    Group1,
    Mov,
    Movs,
    Movsx,
    Movzx,
    Pios,
    Stos,
    Sub,
    Test,
    TwoByte,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OpDesc {
    pub opcode: u8,
    pub optype: OpType,
    pub opflags: OpFlags,
}

impl OpDesc {
    pub fn one_byte(opcode: u8) -> Result<Self, OpCodeError> {
        let mut opdesc = OpDesc {
            opcode,
            optype: OpType::UnSupported,
            opflags: OpFlags::empty(),
        };

        match opcode {
            0x0F => {
                opdesc.optype = OpType::TwoByte;
            }
            0x23 => {
                opdesc.optype = OpType::And;
            }
            0x2B => {
                opdesc.optype = OpType::Sub;
            }
            0x39 | 0x3B => {
                opdesc.optype = OpType::Cmp;
            }
            0x6C => {
                opdesc.optype = OpType::Pios;
                opdesc.opflags.insert(OpFlags::NO_MODRM | OpFlags::BYTE_OP);
            }
            0x6E => {
                opdesc.optype = OpType::Pios;
                opdesc.opflags.insert(OpFlags::NO_MODRM | OpFlags::BYTE_OP);
            }
            0x80 => {
                opdesc.optype = OpType::Group1;
                opdesc.opflags.insert(OpFlags::BYTE_OP | OpFlags::IMM8);
            }
            0x81 => {
                opdesc.optype = OpType::Group1;
                opdesc.opflags.insert(OpFlags::IMM);
            }
            0x83 => {
                opdesc.optype = OpType::Group1;
                opdesc.opflags.insert(OpFlags::IMM8);
            }
            0x84 => {
                opdesc.optype = OpType::Test;
                opdesc.opflags.insert(OpFlags::BYTE_OP);
            }
            0x85 => {
                opdesc.optype = OpType::Test;
            }
            0x88 | 0x8A => {
                opdesc.optype = OpType::Mov;
                opdesc.opflags.insert(OpFlags::BYTE_OP);
            }
            0x89 | 0x8B => {
                opdesc.optype = OpType::Mov;
            }
            0xA1 | 0xA3 => {
                opdesc.optype = OpType::Mov;
                opdesc.opflags.insert(OpFlags::MOFFSET | OpFlags::NO_MODRM);
            }
            0xA4 => {
                opdesc.optype = OpType::Movs;
                opdesc.opflags.insert(OpFlags::NO_MODRM | OpFlags::BYTE_OP);
            }
            0xA5 => {
                opdesc.optype = OpType::Movs;
                opdesc.opflags.insert(OpFlags::NO_MODRM);
            }
            0xAA => {
                opdesc.optype = OpType::Stos;
                opdesc.opflags.insert(OpFlags::NO_MODRM | OpFlags::BYTE_OP);
            }
            0xAB => {
                opdesc.optype = OpType::Stos;
                opdesc.opflags.insert(OpFlags::NO_MODRM);
            }
            0xC6 => {
                opdesc.optype = OpType::Mov;
                opdesc.opflags.insert(OpFlags::IMM8 | OpFlags::BYTE_OP);
            }
            0xC7 => {
                opdesc.optype = OpType::Mov;
                opdesc.opflags.insert(OpFlags::IMM);
            }
            _ => {}
        };

        if opdesc.optype == OpType::UnSupported {
            Err(OpCodeError::OpCode(opcode))
        } else {
            Ok(opdesc)
        }
    }

    pub fn two_byte(opcode: u8) -> Result<Self, OpCodeError> {
        let mut opdesc = OpDesc {
            opcode,
            optype: OpType::UnSupported,
            opflags: OpFlags::empty(),
        };

        match opcode {
            0xB6 | 0xB7 => {
                opdesc.optype = OpType::Movzx;
                opdesc.opflags.insert(OpFlags::BYTE_OP);
            }
            0xBA => {
                opdesc.optype = OpType::BitTest;
                opdesc.opflags.insert(OpFlags::IMM8);
            }
            0xBE => {
                opdesc.optype = OpType::Movsx;
                opdesc.opflags.insert(OpFlags::BYTE_OP);
            }
            _ => {}
        };

        if opdesc.optype == OpType::UnSupported {
            Err(OpCodeError::OpCode(opcode))
        } else {
            Ok(opdesc)
        }
    }
}
