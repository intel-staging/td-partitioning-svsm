// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::error::{ErrExcp, TdxError};
use super::gctx::{
    GuestCpuContext, GuestCpuGPRegCode, GuestCpuMode, GuestCpuRegCode, GuestCpuSegCode,
    PagingLevel, Segment, SegmentType,
};
use super::gmem::{copy_from_gpa, gva2gpa, GuestMemAccessCode};
use super::ioreq::{copy_from_gpa_addrsize, copy_to_gpa_addrsize, AddrSize, IoOperation};
use super::opcode::{OpCodeError, OpDesc, OpFlags, OpType};
use crate::address::{GuestPhysAddr, GuestVirtAddr};
use crate::cpu::idt::common::PageFaultErrCode;
use crate::cpu::registers::RFlags;
use core::arch::asm;

const INST_SIZE: usize = 15;
const PREFIX_SIZE: usize = 4;

#[allow(dead_code)]
#[derive(Debug)]
enum InstrEmulError {
    BadAddrSize,
    BadInstrLen,
    BadIOReq,
    BadEmul(OpType, u8),
    CheckAddr,
    DecodeDisp,
    DecodeMOffset,
    DecodeModRM,
    DecodeOpCode(OpCodeError),
    DecodePrefix,
    GetRawInstr,
    InstrPeek,
    InjectExcp(ErrExcp),
    UnSupportedOpEmul(OpType, u8),
}

impl From<InstrEmulError> for TdxError {
    fn from(e: InstrEmulError) -> Self {
        match e {
            InstrEmulError::InjectExcp(excp) => TdxError::InjectExcp(excp),
            InstrEmulError::BadAddrSize
            | InstrEmulError::BadInstrLen
            | InstrEmulError::DecodeDisp
            | InstrEmulError::DecodeMOffset
            | InstrEmulError::DecodeModRM
            | InstrEmulError::DecodeOpCode(_)
            | InstrEmulError::DecodePrefix
            | InstrEmulError::GetRawInstr
            | InstrEmulError::InstrPeek => TdxError::InjectExcp(ErrExcp::UD),
            _ => TdxError::EmulInstr,
        }
    }
}

#[derive(Copy, Clone, Default, Debug)]
struct ModRM(u8);

const MOD_INDIRECT: u8 = 0;
const MOD_INDIRECT_DISP8: u8 = 1;
const MOD_INDIRECT_DISP32: u8 = 2;
const MOD_DIRECT: u8 = 3;
const RM_SIB: u8 = 4;
const RM_DISP32: u8 = 5;

impl From<u8> for ModRM {
    fn from(val: u8) -> Self {
        ModRM(val)
    }
}

#[derive(PartialEq)]
enum RM {
    Reg(GuestCpuGPRegCode),
    Sib,
    Disp32,
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum Mod {
    Indirect,
    IndirectDisp8,
    IndirectDisp32,
    Direct,
}

impl Default for RM {
    fn default() -> Self {
        RM::Reg(GuestCpuGPRegCode::Rax)
    }
}

impl ModRM {
    fn get_mod(&self) -> Mod {
        let v = (self.0 >> 6) & 0x3;

        match v {
            MOD_INDIRECT => Mod::Indirect,
            MOD_INDIRECT_DISP8 => Mod::IndirectDisp8,
            MOD_INDIRECT_DISP32 => Mod::IndirectDisp32,
            MOD_DIRECT => Mod::Direct,
            _ => {
                unreachable!("Get Mod unreachable");
            }
        }
    }

    fn get_reg(&self) -> u8 {
        (self.0 >> 3) & 0x7
    }

    fn get_rm(&self) -> RM {
        let rm = self.0 & 0x7;
        let r#mod = self.get_mod();

        // RM depends on the Mod value
        if r#mod == Mod::Indirect && rm == RM_DISP32 {
            RM::Disp32
        } else if r#mod != Mod::Direct && rm == RM_SIB {
            RM::Sib
        } else {
            RM::Reg(GuestCpuGPRegCode::try_from(rm).unwrap())
        }
    }
}

#[derive(Copy, Clone, Default, Debug)]
struct Sib(u8);

impl From<u8> for Sib {
    fn from(val: u8) -> Self {
        Sib(val)
    }
}

impl Sib {
    fn get_scale(&self) -> u8 {
        (self.0 >> 6) & 0x3
    }

    fn get_index(&self) -> u8 {
        (self.0 >> 3) & 0x7
    }

    fn get_base(&self) -> u8 {
        self.0 & 0x7
    }
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Default, Debug)]
    struct PrefixFlags: u16 {
        const REX_W                 = 1 << 0;
        const REX_R                 = 1 << 1;
        const REX_X                 = 1 << 2;
        const REX_B                 = 1 << 3;
        const REX_P                 = 1 << 4;
        const REPZ_P                = 1 << 5;
        const REPNZ_P               = 1 << 6;
        const OPSIZE_OVERRIDE       = 1 << 7;
        const ADDRSIZE_OVERRIDE     = 1 << 8;
    }
}

bitflags::bitflags! {
    struct RexPrefix: u8 {
        const B     = 1 << 0;
        const X     = 1 << 1;
        const R     = 1 << 2;
        const W     = 1 << 3;
    }
}

fn calculate_gla(
    vcpu_mode: GuestCpuMode,
    seg: GuestCpuSegCode,
    desc: &Segment,
    offset: u64,
    addrsize: AddrSize,
) -> Result<GuestVirtAddr, InstrEmulError> {
    if addrsize == AddrSize::ZeroByte {
        return Err(InstrEmulError::BadAddrSize);
    }

    let offset = offset & addrsize.mask();
    let glasize = if vcpu_mode.is_bit64() {
        AddrSize::EightBytes
    } else {
        AddrSize::FourBytes
    };
    let segbase =
        if vcpu_mode.is_bit64() && seg != GuestCpuSegCode::FS && seg != GuestCpuSegCode::GS {
            0
        } else {
            desc.base
        };

    Ok(GuestVirtAddr::from((segbase + offset) & glasize.mask()))
}

fn canonical_check(vcpu_mode: GuestCpuMode, gla: u64) -> bool {
    match vcpu_mode {
        GuestCpuMode::Bit64(level) => {
            let virtaddr_bits = if level == PagingLevel::Level4 { 48 } else { 57 };
            let mask = !((1 << virtaddr_bits) - 1);
            if gla & (1 << (virtaddr_bits - 1)) != 0 {
                gla & mask == mask
            } else {
                gla & mask == 0
            }
        }
        _ => true,
    }
}

macro_rules! getcc_asm {
    ($x:ident, $y:ident, $rflags:ident, u8) => {
        asm!(
            "sub {0}, {1}; pushfq; pop {2}",
            inout(reg_byte) $x => _,
            in(reg_byte) $y,
            out(reg) $rflags,
            options(nomem, preserves_flags)
        )
    };
    ($x:ident, $y:ident, $rflags:ident, u16) => {
        asm!(
            "sub {0:x}, {1:x}; pushfq; pop {2}",
            inout(reg) $x => _,
            in(reg) $y,
            out(reg) $rflags,
            options(nomem, preserves_flags)
        )
    };
    ($x:ident, $y:ident, $rflags:ident, u32) => {
        asm!(
            "sub {0:e}, {1:e}; pushfq; pop {2}",
            inout(reg) $x => _,
            in(reg) $y,
            out(reg) $rflags,
            options(nomem, preserves_flags)
        )
    };
    ($x:ident, $y:ident, $rflags:ident, u64) => {
        asm!(
            "sub {0}, {1}; pushfq; pop {2}",
            inout(reg) $x => _,
            in(reg) $y,
            out(reg) $rflags,
            options(nomem, preserves_flags)
        )
    };
}

macro_rules! getcc_func {
    ($func:ident, $type:tt) => {
        fn $func(x: $type, y: $type) -> RFlags {
            let rflags: u64;
            unsafe {
                getcc_asm!(x, y, rflags, $type);
            }
            RFlags::from_bits_truncate(rflags)
        }
    };
}

getcc_func!(getcc_u8, u8);
getcc_func!(getcc_u16, u16);
getcc_func!(getcc_u32, u32);
getcc_func!(getcc_u64, u64);

fn getcc(size: AddrSize, x: u64, y: u64) -> RFlags {
    match size {
        AddrSize::OneByte => getcc_u8(x as u8, y as u8),
        AddrSize::TwoBytes => getcc_u16(x as u16, y as u16),
        AddrSize::FourBytes => getcc_u32(x as u32, y as u32),
        AddrSize::EightBytes => getcc_u64(x, y),
        _ => unreachable!("getcc unreachable"),
    }
}

type InstrBytes = [u8; INST_SIZE];

#[derive(Copy, Clone, Default, Debug)]
struct RawInstrCode {
    // Instruction bytes
    code: InstrBytes,
    // Size of the instruction
    num_valid: usize,
    num_processed: usize,
}

impl RawInstrCode {
    fn new(ctx: &GuestCpuContext, instr_len: usize) -> Result<Self, InstrEmulError> {
        if instr_len > INST_SIZE {
            return Err(InstrEmulError::BadInstrLen);
        }
        let cs_desc = ctx.get_seg(GuestCpuSegCode::CS);
        let rip = GuestVirtAddr::from(ctx.get_rip());
        let gva = calculate_gla(
            ctx.get_cpu_mode(),
            GuestCpuSegCode::CS,
            &cs_desc,
            u64::from(rip),
            AddrSize::EightBytes,
        )?;

        let gpa = if let Some(gpa) = gva2gpa(ctx, gva, GuestMemAccessCode::FETCH).map_err(|e| {
            log::error!("Failed to translate rip gva 0x{:x} to gpa: {:?}", gva, e);
            InstrEmulError::GetRawInstr
        })? {
            gpa
        } else {
            return Err(InstrEmulError::InjectExcp(ErrExcp::PF(
                gva,
                PageFaultErrCode::I,
            )));
        };

        let mut code: InstrBytes = InstrBytes::default();
        copy_from_gpa::<InstrBytes>(gpa)
            .map_err(|e| {
                log::error!("Failed to read instruction raw code: {:?}", e);
                InstrEmulError::GetRawInstr
            })?
            .iter()
            .enumerate()
            .filter(|&(i, _)| i < instr_len)
            .for_each(|(i, c)| {
                code[i] = *c;
            });

        Ok(RawInstrCode {
            code,
            num_valid: instr_len,
            num_processed: 0,
        })
    }

    fn peek(&self) -> Result<u8, InstrEmulError> {
        if self.num_processed < self.num_valid {
            Ok(self.code[self.num_processed])
        } else {
            Err(InstrEmulError::InstrPeek)
        }
    }

    fn advance(&mut self) {
        self.num_processed += 1
    }
}

pub struct InstrEmul<'a> {
    ctx: &'a mut GuestCpuContext,
    vcpu_mode: GuestCpuMode,
    // Instruction op code
    instr: RawInstrCode,

    addrsize: AddrSize,
    opsize: AddrSize,
    // Prefix
    flags: PrefixFlags,

    // ModR/M byte
    modrm: ModRM,
    // Extended R/M and Reg
    rm: RM,
    reg: u8,

    // SIB byte
    sib: Sib,
    // Extended Index and Base
    index: u8,
    base: u8,

    disp_bytes: AddrSize,
    // Optional addr displacement
    displacement: i64,

    imm_bytes: AddrSize,
    // Optional immediate operand
    immediate: i64,

    modrm_reg: GuestCpuGPRegCode,
    scale: u8,
    base_reg: Option<GuestCpuRegCode>,
    index_reg: Option<GuestCpuGPRegCode>,
    override_seg: Option<GuestCpuSegCode>,

    // Opcode description
    op: OpDesc,
}

impl<'a> InstrEmul<'a> {
    fn new(ctx: &'a mut GuestCpuContext, instr_len: usize) -> Result<Self, TdxError> {
        let vcpu_mode = ctx.get_cpu_mode();

        RawInstrCode::new(ctx, instr_len)
            .map(|instr| InstrEmul {
                ctx,
                vcpu_mode,
                instr,
                addrsize: AddrSize::ZeroByte,
                opsize: AddrSize::ZeroByte,
                flags: PrefixFlags::default(),
                modrm: ModRM::default(),
                rm: RM::default(),
                reg: 0,
                sib: Sib::default(),
                index: 0,
                base: 0,
                disp_bytes: AddrSize::ZeroByte,
                displacement: 0,
                imm_bytes: AddrSize::ZeroByte,
                immediate: 0,
                modrm_reg: GuestCpuGPRegCode::Rax,
                scale: 0,
                base_reg: None,
                index_reg: None,
                override_seg: None,
                op: OpDesc::default(),
            })
            .map_err(|e| {
                log::error!("Failed to create InstrEmul: {:?}", e);
                TdxError::from(e)
            })
    }

    fn decode_seg_override_prefix(&mut self, code: u8) -> Result<(), InstrEmulError> {
        match code {
            0x2E => self.override_seg = Some(GuestCpuSegCode::CS),
            0x36 => self.override_seg = Some(GuestCpuSegCode::SS),
            0x3E => self.override_seg = Some(GuestCpuSegCode::DS),
            0x26 => self.override_seg = Some(GuestCpuSegCode::ES),
            0x64 => self.override_seg = Some(GuestCpuSegCode::FS),
            0x65 => self.override_seg = Some(GuestCpuSegCode::GS),
            _ => return Err(InstrEmulError::DecodePrefix),
        }

        Ok(())
    }

    fn decode_rex_prefix(&mut self, code: u8) {
        if !self.vcpu_mode.is_bit64() {
            return;
        }

        self.flags.insert(PrefixFlags::REX_P);
        let rex = RexPrefix::from_bits_truncate(code);
        if rex.contains(RexPrefix::W) {
            self.flags.insert(PrefixFlags::REX_W);
        }
        if rex.contains(RexPrefix::R) {
            self.flags.insert(PrefixFlags::REX_R);
        }
        if rex.contains(RexPrefix::X) {
            self.flags.insert(PrefixFlags::REX_X);
        }
        if rex.contains(RexPrefix::B) {
            self.flags.insert(PrefixFlags::REX_B);
        }
    }

    fn decode_prefix(&mut self, code: u8) -> Result<bool, InstrEmulError> {
        let mut last = false;

        match code {
            0x66 => self.flags.insert(PrefixFlags::OPSIZE_OVERRIDE),
            0x67 => self.flags.insert(PrefixFlags::ADDRSIZE_OVERRIDE),
            0xF3 => self.flags.insert(PrefixFlags::REPZ_P),
            0xF2 => self.flags.insert(PrefixFlags::REPNZ_P),
            0x40..=0x4F => {
                self.decode_rex_prefix(code);
                last = true;
            }
            _ => self.decode_seg_override_prefix(code)?,
        }

        Ok(last)
    }

    fn decode_op_addr_size(&mut self, cs: &Segment) {
        (self.addrsize, self.opsize) = if self.vcpu_mode.is_bit64() {
            (
                if self.flags.contains(PrefixFlags::ADDRSIZE_OVERRIDE) {
                    AddrSize::FourBytes
                } else {
                    AddrSize::EightBytes
                },
                if self.flags.contains(PrefixFlags::REX_W) {
                    AddrSize::EightBytes
                } else if self.flags.contains(PrefixFlags::OPSIZE_OVERRIDE) {
                    AddrSize::TwoBytes
                } else {
                    AddrSize::FourBytes
                },
            )
        } else if cs.attr & 0x4000 != 0 {
            // Default address and operand sizes are 32-bits
            (
                if self.flags.contains(PrefixFlags::ADDRSIZE_OVERRIDE) {
                    AddrSize::TwoBytes
                } else {
                    AddrSize::FourBytes
                },
                if self.flags.contains(PrefixFlags::OPSIZE_OVERRIDE) {
                    AddrSize::TwoBytes
                } else {
                    AddrSize::FourBytes
                },
            )
        } else {
            // Default address and operand sizes are 16-bits
            (
                if self.flags.contains(PrefixFlags::ADDRSIZE_OVERRIDE) {
                    AddrSize::FourBytes
                } else {
                    AddrSize::TwoBytes
                },
                if self.flags.contains(PrefixFlags::OPSIZE_OVERRIDE) {
                    AddrSize::FourBytes
                } else {
                    AddrSize::TwoBytes
                },
            )
        };
    }

    fn decode_prefixes(&mut self) -> Result<(), InstrEmulError> {
        for _ in 0..PREFIX_SIZE {
            let code = self.instr.peek()?;
            let ret = self.decode_prefix(code);
            if ret.is_err() {
                break;
            }
            self.instr.advance();

            if ret.unwrap() {
                break;
            }
        }

        let cs = self.ctx.get_seg(GuestCpuSegCode::CS);
        self.decode_op_addr_size(&cs);

        Ok(())
    }

    fn decode_opcode(&mut self) -> Result<(), InstrEmulError> {
        let op = OpDesc::one_byte(self.instr.peek()?).map_err(InstrEmulError::DecodeOpCode)?;
        self.instr.advance();

        self.op = if op.optype == OpType::TwoByte {
            let two_byte_op =
                OpDesc::two_byte(self.instr.peek()?).map_err(InstrEmulError::DecodeOpCode)?;
            self.instr.advance();
            two_byte_op
        } else {
            op
        };

        if self.op.opflags.contains(OpFlags::BYTE_OP) {
            self.opsize = AddrSize::OneByte;
        } else if self.op.opflags.contains(OpFlags::WORD_OP) {
            self.opsize = AddrSize::TwoBytes;
        }

        Ok(())
    }

    fn decode_modrm(&mut self) -> Result<(), InstrEmulError> {
        if self.op.opflags.contains(OpFlags::NO_MODRM) {
            return Ok(());
        }

        if self.vcpu_mode == GuestCpuMode::Real {
            return Err(InstrEmulError::DecodeModRM);
        }

        self.modrm = ModRM::from(self.instr.peek()?);

        let r#mod = self.modrm.get_mod();
        self.rm = self.modrm.get_rm();
        self.reg = self.modrm.get_reg() | ((self.flags.contains(PrefixFlags::REX_R) as u8) << 3);
        self.modrm_reg = GuestCpuGPRegCode::try_from(self.reg).unwrap();

        // As the instruction emulator is used during handling EPT fault, A
        // direct addressing mode makes no sense in the context. There has
        // to be a memory access involved to cause the EPT fault.
        if r#mod == Mod::Direct {
            return Err(InstrEmulError::DecodeModRM);
        }

        // SDM Vol2 Table 2-5: Special Cases of REX Encodings
        // For mod=0 r/m=5 and mod!=3 r/m=4, the 'b' bit in the REX
        // prefix is 'don't care' in these two cases.
        //
        // RM::Disp32 represent mod=0 r/m=5
        // RM::Sib represent mod!=3 r/m=4
        // RM::Reg(r) represent the other cases.
        //
        // So set 'b' bit for the other cases.
        match self.rm {
            RM::Reg(r) => {
                let ext_r = GuestCpuGPRegCode::try_from(
                    r as u8 | ((self.flags.contains(PrefixFlags::REX_B) as u8) << 3),
                )
                .unwrap();
                self.rm = RM::Reg(ext_r);
                self.base_reg = Some(GuestCpuRegCode::GP(ext_r));
                match r#mod {
                    Mod::IndirectDisp8 => self.disp_bytes = AddrSize::OneByte,
                    Mod::IndirectDisp32 => self.disp_bytes = AddrSize::FourBytes,
                    Mod::Indirect | Mod::Direct => {}
                };
            }
            RM::Disp32 => {
                self.disp_bytes = AddrSize::FourBytes;
                // SDM Vol2 Table 2-7: RIP-Relative Addressing
                // In 64bit mode, mod=0 r/m=101 implies [rip] + disp32
                // whereas in compatibility mode it just implies disp32.
                self.base_reg = if self.vcpu_mode.is_bit64() {
                    Some(GuestCpuRegCode::Rip)
                } else {
                    None
                };
            }
            RM::Sib => {}
        };

        self.instr.advance();
        Ok(())
    }

    fn decode_sib(&mut self) -> Result<(), InstrEmulError> {
        // Process only if SIB byte is present
        if self.rm != RM::Sib {
            return Ok(());
        }

        self.sib = Sib::from(self.instr.peek()?);
        self.index = self.sib.get_index() | ((self.flags.contains(PrefixFlags::REX_X) as u8) << 3);
        self.base = self.sib.get_base() | ((self.flags.contains(PrefixFlags::REX_B) as u8) << 3);

        let r#mod = self.modrm.get_mod();
        match r#mod {
            Mod::IndirectDisp8 => {
                self.disp_bytes = AddrSize::OneByte;
                self.base_reg = Some(GuestCpuRegCode::GP(
                    GuestCpuGPRegCode::try_from(self.base).unwrap(),
                ));
            }
            Mod::IndirectDisp32 => {
                self.disp_bytes = AddrSize::FourBytes;
                self.base_reg = Some(GuestCpuRegCode::GP(
                    GuestCpuGPRegCode::try_from(self.base).unwrap(),
                ));
            }
            Mod::Indirect => {
                // SMD Vol 2 Table 2-5 Special Cases of REX Encoding
                // Base register is unused if mod=0 base=RBP/R13.
                self.base_reg = if self.base == GuestCpuGPRegCode::Rbp as u8
                    || self.base == GuestCpuGPRegCode::R13 as u8
                {
                    self.disp_bytes = AddrSize::FourBytes;
                    None
                } else {
                    Some(GuestCpuRegCode::GP(
                        GuestCpuGPRegCode::try_from(self.base).unwrap(),
                    ))
                }
            }
            Mod::Direct => {}
        };

        // SMD Vol 2 Table 2-5 Special Cases of REX Encoding
        // Index register not used when index=RSP
        if self.index != GuestCpuGPRegCode::Rsp as u8 {
            self.index_reg = Some(GuestCpuGPRegCode::try_from(self.index).unwrap());
            // 'scale' makes sense only in the context of an index register
            self.scale = 1 << self.sib.get_scale();
        }

        self.instr.advance();
        Ok(())
    }

    fn decode_displacement(&mut self) -> Result<(), InstrEmulError> {
        match self.disp_bytes {
            AddrSize::ZeroByte => Ok(()),
            AddrSize::OneByte | AddrSize::FourBytes => {
                let mut buf = [0; 4];

                for v in buf.iter_mut().take(self.disp_bytes as usize) {
                    *v = self.instr.peek()?;
                    self.instr.advance();
                }

                self.displacement = if self.disp_bytes == AddrSize::OneByte {
                    buf[0] as i8 as i64
                } else {
                    i32::from_le_bytes(buf) as i64
                };

                Ok(())
            }
            _ => {
                log::error!(
                    "Decode displacement invalid disp_bytes {}",
                    self.disp_bytes as u8
                );
                Err(InstrEmulError::DecodeDisp)
            }
        }
    }

    fn decode_immediate(&mut self) -> Result<(), InstrEmulError> {
        // Figure out immediate operand size (if any)
        self.imm_bytes = if self.op.opflags.contains(OpFlags::IMM) {
            match self.opsize {
                // SDM Vol 2 2.2.1.5 "Immediates"
                // In 64-bit mode the typical size of immediate operands
                // remains 32-bits. When the operand size if 64-bits, the
                // processor sign-extends all immediates to 64-bits prior
                // to their use.
                AddrSize::FourBytes | AddrSize::EightBytes => AddrSize::FourBytes,
                _ => AddrSize::TwoBytes,
            }
        } else if self.op.opflags.contains(OpFlags::IMM8) {
            AddrSize::OneByte
        } else {
            // No opflags on immediate operand size
            AddrSize::ZeroByte
        };

        if self.imm_bytes == AddrSize::ZeroByte {
            return Ok(());
        }

        let mut buf = [0; 4];

        for v in buf.iter_mut().take(self.imm_bytes as usize) {
            *v = self.instr.peek()?;
            self.instr.advance();
        }

        self.immediate = match self.imm_bytes {
            AddrSize::OneByte => buf[0] as i8 as i64,
            AddrSize::TwoBytes => i16::from_le_bytes([buf[0], buf[1]]) as i64,
            AddrSize::FourBytes => i32::from_le_bytes(buf) as i64,
            _ => {
                unreachable!("Decode immediate unreachable");
            }
        };

        Ok(())
    }

    fn decode_moffset(&mut self) -> Result<(), InstrEmulError> {
        if !self.op.opflags.contains(OpFlags::MOFFSET) {
            return Ok(());
        }

        match self.addrsize {
            AddrSize::ZeroByte | AddrSize::OneByte => {
                log::error!("Decode moffset invalid addrsize {:?}", self.addrsize);
                Err(InstrEmulError::DecodeMOffset)
            }
            _ => {
                // SDM Vol 2 Section 2.2.1.4, "Direct Memory-Offset MOVs"
                // In 64-bit mode, direct memory-offset forms of the MOV
                // instruction are extended to specify a 64-bit immediate
                // absolute address.
                //
                // The memory offset size follows the address-size of the instruction.
                let mut buf = [0; 8];
                for v in buf.iter_mut().take(self.addrsize as usize) {
                    *v = self.instr.peek()?;
                    self.instr.advance();
                }
                self.displacement = i64::from_le_bytes(buf);
                Ok(())
            }
        }
    }

    pub fn decode_instr(ctx: &'a mut GuestCpuContext, instr_len: usize) -> Result<Self, TdxError> {
        let mut instr_emul = Self::new(ctx, instr_len)?;

        instr_emul.decode_prefixes().map_err(|e| {
            log::error!("Failed to decode prefix: {:?}", e);
            TdxError::from(e)
        })?;

        instr_emul.decode_opcode().map_err(|e| {
            log::error!("Failed to decode opcode: {:?}", e);
            TdxError::from(e)
        })?;

        instr_emul.decode_modrm().map_err(|e| {
            log::error!("Failed to decode modrm: {:?}", e);
            TdxError::from(e)
        })?;

        instr_emul.decode_sib().map_err(|e| {
            log::error!("Failed to decode SIB: {:?}", e);
            TdxError::from(e)
        })?;

        instr_emul.decode_displacement().map_err(|e| {
            log::error!("Failed to decode displacement: {:?}", e);
            TdxError::from(e)
        })?;

        instr_emul.decode_immediate().map_err(|e| {
            log::error!("Failed to decode immediate: {:?}", e);
            TdxError::from(e)
        })?;

        instr_emul.decode_moffset().map_err(|e| {
            log::error!("Failed to decode moffset : {:?}", e);
            TdxError::from(e)
        })?;

        Ok(instr_emul)
    }

    pub fn get_opsize(&self) -> AddrSize {
        self.opsize
    }

    fn update_gpreg(&mut self, reg: GuestCpuGPRegCode, val: u64, size: AddrSize) {
        let new_val = match size {
            AddrSize::ZeroByte => self.ctx.get_gpreg(reg),
            AddrSize::OneByte | AddrSize::TwoBytes => {
                let old_val = self.ctx.get_gpreg(reg);
                (val & size.mask()) | (old_val & !size.mask())
            }
            AddrSize::FourBytes => val & size.mask(),
            AddrSize::EightBytes => val,
        };

        self.ctx.set_gpreg(reg, new_val);
    }

    fn update_rflags(&mut self, new_rflags: RFlags) {
        let reg_val = self.ctx.get_rflags();
        let status =
            (RFlags::CF | RFlags::PF | RFlags::AF | RFlags::ZF | RFlags::SF | RFlags::OF).bits();

        self.ctx.set_rflags(reg_val & !status | new_rflags.bits());
    }

    fn calculate_bytereg(&self) -> (GuestCpuGPRegCode, bool) {
        // 64-bit mode imposes limitations on accessing legacy high byte
        // registers (lhbr).
        //
        // The legacy high-byte registers cannot be addressed if the REX
        // prefix is present. In this case the values 4, 5, 6 and 7 of the
        // 'ModRM:reg' field address %spl, %bpl, %sil and %dil respectively.
        //
        // If the REX prefix is not present then the values 4, 5, 6 and 7
        // of the 'ModRM:reg' field address the legacy high-byte registers,
        // %ah, %ch, %dh and %bh respectively.
        if !self.flags.contains(PrefixFlags::REX_P) && (self.reg & 0x4) != 0 {
            return (GuestCpuGPRegCode::try_from(self.reg & 0x3).unwrap(), true);
        }

        (self.modrm_reg, false)
    }

    fn read_bytereg(&self) -> u8 {
        let (reg, lhbr) = self.calculate_bytereg();
        let val = self.ctx.get_gpreg(reg);

        // To obtain the value of a legacy high byte register shift the
        // base register right by 8 bits (%ah = %rax >> 8).
        if lhbr {
            (val >> 8) as u8
        } else {
            val as u8
        }
    }

    fn write_bytereg(&mut self, val: u8) {
        let (reg, lhbr) = self.calculate_bytereg();
        let old_val = self.ctx.get_gpreg(reg);
        let mask = (AddrSize::OneByte).mask();

        let new_val = if lhbr {
            (val as u64) << 8 | (old_val & !(mask << 8))
        } else {
            (val as u64) | (old_val & !mask)
        };

        self.ctx.set_gpreg(reg, new_val);
    }

    fn get_opcode_addr_check(
        &self,
        seg: GuestCpuSegCode,
        reg: GuestCpuGPRegCode,
        writable: bool,
    ) -> Result<GuestPhysAddr, InstrEmulError> {
        let desc = self.ctx.get_seg(seg);

        if self.vcpu_mode.is_bit64() {
            match self.addrsize {
                AddrSize::FourBytes | AddrSize::EightBytes => {}
                _ => return Err(InstrEmulError::InjectExcp(ErrExcp::GP(0))),
            }
        } else {
            match self.addrsize {
                AddrSize::FourBytes | AddrSize::TwoBytes => {
                    match desc.segtype() {
                        // Not allow System segment
                        SegmentType::System => {
                            return Err(InstrEmulError::InjectExcp(ErrExcp::GP(0)))
                        }
                        _ => {
                            // Not allow read from execute-only code segment
                            if !writable && !desc.is_code_readable() {
                                return Err(InstrEmulError::InjectExcp(ErrExcp::GP(0)));
                            }
                            // Not allow write to read-only data segment
                            if writable && !desc.is_data_writable() {
                                return Err(InstrEmulError::InjectExcp(ErrExcp::GP(0)));
                            }
                        }
                    }
                }
                _ => return Err(InstrEmulError::InjectExcp(ErrExcp::GP(0))),
            }
        }

        let offset = self.ctx.get_gpreg(reg);
        let gva = calculate_gla(self.vcpu_mode, seg, &desc, offset, self.addrsize)?;

        if !canonical_check(self.vcpu_mode, u64::from(gva)) {
            return Err(InstrEmulError::InjectExcp(ErrExcp::GP(0)));
        }

        gva2gpa(
            self.ctx,
            gva,
            if writable {
                GuestMemAccessCode::WRITE
            } else {
                GuestMemAccessCode::empty()
            },
        )
        .map_err(|e| {
            log::error!(
                "Decoder check_di failed to translate gva 0x{:x}: {:?}",
                gva,
                e
            );
            InstrEmulError::CheckAddr
        })?
        .ok_or(InstrEmulError::InjectExcp(ErrExcp::PF(
            gva,
            PageFaultErrCode::W,
        )))
    }

    fn emulate_and(&mut self, io_op: &IoOperation) -> Result<(), InstrEmulError> {
        let val = match self.op.opcode {
            0x23 => {
                // AND reg (ModRM:reg) and mem (ModRM:r/m) and store the
                // result in reg.
                //
                // 23/r		and r16, r/m16
                // 23/r		and r32, r/m32
                // REX.W + 23/r	and r64, r/m64
                let val = self.ctx.get_gpreg(self.modrm_reg)
                    & io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)?;
                self.update_gpreg(self.modrm_reg, val, self.opsize);
                val
            }
            _ => {
                return Err(InstrEmulError::UnSupportedOpEmul(
                    self.op.optype,
                    self.op.opcode,
                ))
            }
        };

        // OF and CF are cleared; the SF, ZF and PF flags are set
        // according to the result; AF is undefined.
        //
        // The updated status flags are obtained by subtracting 0 from
        // 'result'.
        let rflags = getcc(self.opsize, val, 0);
        self.update_rflags(rflags.intersection(RFlags::PF | RFlags::ZF | RFlags::SF));

        Ok(())
    }

    fn emulate_bittest(&mut self, io_op: &IoOperation) -> Result<(), InstrEmulError> {
        // 0F BA is a Group 8 extended opcode.
        //
        // Currently we only emulate the 'Bit Test' instruction which is
        // identified by a ModR/M:reg encoding of 100b.
        if self.reg & 7 != 4 {
            return Err(InstrEmulError::UnSupportedOpEmul(self.op.optype, self.reg));
        }

        let mut reg_val = self.ctx.get_rflags();
        // Intel SDM, Vol 2, Table 3-2:
        // "Range of Bit Positions Specified by Bit Offset Operands"
        let bitoff = (self.immediate as u64) & self.opsize.mask();

        if io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)? & (1 << bitoff) != 0 {
            reg_val |= RFlags::CF.bits();
        } else {
            reg_val &= !RFlags::CF.bits();
        }

        self.ctx.set_rflags(reg_val);

        Ok(())
    }

    fn emulate_cmp(&mut self, io_op: &IoOperation) -> Result<(), InstrEmulError> {
        let (x, y) = match self.op.opcode {
            0x39 | 0x3B => {
                // 39/r		CMP r/m16, r16
                // 39/r		CMP r/m32, r32
                // REX.W 39/r	CMP r/m64, r64
                //
                // 3B/r		CMP r16, r/m16
                // 3B/r		CMP r32, r/m32
                // REX.W + 3B/r	CMP r64, r/m64
                //
                // Compare the first operand with the second operand and
                // set status flags in EFLAGS register. The comparison
                // is performed by subtracting the second operand from
                // the first operand and then setting the status flags.
                if self.op.opcode == 0x3B {
                    (
                        self.ctx.get_gpreg(self.modrm_reg),
                        io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)?,
                    )
                } else {
                    (
                        io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)?,
                        self.ctx.get_gpreg(self.modrm_reg),
                    )
                }
            }
            0x80 | 0x81 | 0x83 => {
                // 80 /7		cmp r/m8, imm8
                // REX + 80 /7		cmp r/m8, imm8
                //
                // 81 /7		cmp r/m16, imm16
                // 81 /7		cmp r/m32, imm32
                // REX.W + 81 /7	cmp r/m64, imm32 sign-extended
                //                      to 64
                //
                // 83 /7		cmp r/m16, imm8 sign-extended
                //                      to 16
                // 83 /7		cmp r/m32, imm8 sign-extended
                //                      to 32
                // REX.W + 83 /7	cmp r/m64, imm8 sign-extended
                //                      to 64
                //
                // Compare mem (ModRM:r/m) with immediate and set
                // status flags according to the results.  The
                // comparison is performed by subtracting the
                // immediate from the first operand and then setting
                // the status flags.
                (
                    io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)?,
                    self.immediate as u64,
                )
            }
            _ => {
                return Err(InstrEmulError::UnSupportedOpEmul(
                    self.op.optype,
                    self.op.opcode,
                ))
            }
        };

        let rflags = getcc(self.opsize, x, y);
        self.update_rflags(rflags.intersection(
            RFlags::CF | RFlags::PF | RFlags::AF | RFlags::ZF | RFlags::SF | RFlags::OF,
        ));

        Ok(())
    }

    fn emulate_group1(&mut self, io_op: &IoOperation) -> Result<(), InstrEmulError> {
        match self.reg & 7 {
            // AND
            4 => self.emulate_and(io_op),
            // CMP
            7 => self.emulate_cmp(io_op),
            _ => Err(InstrEmulError::UnSupportedOpEmul(self.op.optype, self.reg)),
        }
    }

    fn emulate_mov(&mut self, io_op: &mut IoOperation) -> Result<(), InstrEmulError> {
        match self.op.opcode {
            0x88 => {
                // Mov byte from reg (ModRM:reg) to mem (ModRM:r/m)
                // 88/r:	mov r/m8, r8
                // REX + 88/r:	mov r/m8, r8 (%ah, %ch, %dh, %bh not available)
                io_op.set_write_data(self.read_bytereg() as u64);
            }
            0x89 => {
                // MOV from reg (ModRM:reg) to mem (ModRM:r/m)
                // 89/r:	mov r/m16, r16
                // 89/r:	mov r/m32, r32
                // REX.W + 89/r	mov r/m64, r64
                let val = self.ctx.get_gpreg(self.modrm_reg);
                io_op.set_write_data(val & self.opsize.mask());
            }
            0x8A => {
                // MOV byte from mem (ModRM:r/m) to reg (ModRM:reg)
                // 8A/r:	mov r8, r/m8
                // REX + 8A/r:	mov r8, r/m8
                self.write_bytereg(io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)? as u8);
            }
            0x8B => {
                // MOV from mem (ModRM:r/m) to reg (ModRM:reg)
                // 8B/r:	mov r16, r/m16
                // 8B/r:	mov r32, r/m32
                // REX.W 8B/r:	mov r64, r/m64
                self.update_gpreg(
                    self.modrm_reg,
                    io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)?,
                    self.opsize,
                );
            }
            0xA1 => {
                // MOV from seg:moffset to AX/EAX/RAX
                // A1:		mov AX, moffs16
                // A1:		mov EAX, moffs32
                // REX.W + A1:	mov RAX, moffs64
                self.update_gpreg(
                    GuestCpuGPRegCode::Rax,
                    io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)?,
                    self.opsize,
                );
            }
            0xA3 => {
                // MOV from AX/EAX/RAX to seg:moffset
                // A3:		mov moffs16, AX
                // A3:		mov moffs32, EAX
                // REX.W + A3:	mov moffs64, RAX
                let val = self.ctx.get_gpreg(GuestCpuGPRegCode::Rax);
                io_op.set_write_data(val & self.opsize.mask());
            }
            0xC6 => {
                // MOV from imm8 to mem (ModRM:r/m)
                // C6/0		mov r/m8, imm8
                // REX + C6/0	mov r/m8, imm8
                io_op.set_write_data(self.immediate as u64);
            }
            0xC7 => {
                // MOV from imm16/imm32 to mem (ModRM:r/m)
                // C7/0		mov r/m16, imm16
                // C7/0		mov r/m32, imm32
                // REX.W + C7/0	mov r/m64, imm32
                // (sign-extended to 64-bits)
                io_op.set_write_data((self.immediate as u64) & self.opsize.mask());
            }
            _ => {
                return Err(InstrEmulError::UnSupportedOpEmul(
                    self.op.optype,
                    self.op.opcode,
                ))
            }
        }

        Ok(())
    }

    fn emulate_movs(&mut self, io_op: &mut IoOperation) -> Result<(), InstrEmulError> {
        let repeat_count = if self.flags.contains(PrefixFlags::REPZ_P)
            | self.flags.contains(PrefixFlags::REPNZ_P)
        {
            let rcx = self.ctx.get_gpreg(GuestCpuGPRegCode::Rcx);

            // The count register is depending on the address size of the
            // instruction.
            if rcx & self.addrsize.mask() == 0 {
                return Ok(());
            }
            Some(rcx)
        } else {
            None
        };

        if io_op.is_read() {
            // Write back mmio-read-value to guest memory
            let gpa =
                self.get_opcode_addr_check(GuestCpuSegCode::ES, GuestCpuGPRegCode::Rdi, true)?;
            let val = io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)?;
            copy_to_gpa_addrsize(gpa, self.opsize, val).map_err(|e| {
                log::error!("Failed to copy MMIO read data to guest memory: {:?}", e);
                InstrEmulError::BadEmul(self.op.optype, self.op.opcode)
            })?;
        } else {
            // Read mmio-write-data from guest memory
            let seg = self.override_seg.map_or(GuestCpuSegCode::DS, |s| s);
            let gpa = self.get_opcode_addr_check(seg, GuestCpuGPRegCode::Rsi, false)?;
            io_op.set_write_data(copy_from_gpa_addrsize(gpa, self.opsize).map_err(|e| {
                log::error!("Failed to copy MMIO write data from guest memory: {:?}", e);
                InstrEmulError::BadEmul(self.op.optype, self.op.opcode)
            })?);
        }

        // Update registers
        let rflags = RFlags::from_bits_truncate(self.ctx.get_rflags());
        if rflags.contains(RFlags::DF) {
            self.update_gpreg(
                GuestCpuGPRegCode::Rsi,
                self.ctx.get_gpreg(GuestCpuGPRegCode::Rsi) - self.opsize as u8 as u64,
                self.addrsize,
            );
            self.update_gpreg(
                GuestCpuGPRegCode::Rdi,
                self.ctx.get_gpreg(GuestCpuGPRegCode::Rdi) - self.opsize as u8 as u64,
                self.addrsize,
            );
        } else {
            self.update_gpreg(
                GuestCpuGPRegCode::Rsi,
                self.ctx.get_gpreg(GuestCpuGPRegCode::Rsi) + self.opsize as u8 as u64,
                self.addrsize,
            );
            self.update_gpreg(
                GuestCpuGPRegCode::Rdi,
                self.ctx.get_gpreg(GuestCpuGPRegCode::Rdi) + self.opsize as u8 as u64,
                self.addrsize,
            );
        }

        if let Some(mut rcx) = repeat_count {
            // Update counter in RCX
            rcx -= 1;
            self.update_gpreg(GuestCpuGPRegCode::Rcx, rcx, self.addrsize);

            if rcx & self.addrsize.mask() != 0 {
                io_op.set_retry();
            }
        }

        Ok(())
    }

    fn emulate_movx(&mut self, io_op: &IoOperation) -> Result<(), InstrEmulError> {
        match self.op.opcode {
            0xB6 => {
                // MOV and zero extend byte from mem (ModRM:r/m) to
                // reg (ModRM:reg).
                //
                // 0F B6/r		movzx r16, r/m8
                // 0F B6/r		movzx r32, r/m8
                // REX.W + 0F B6/r	movzx r64, r/m8
                self.update_gpreg(
                    self.modrm_reg,
                    io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)? as u8 as u64,
                    self.opsize,
                );
            }
            0xB7 => {
                // MOV and zero extend word from mem (ModRM:r/m) to
                // reg (ModRM:reg).
                //
                // 0F B7/r		movzx r32, r/m16
                // REX.W + 0F B7/r	movzx r64, r/m16
                self.update_gpreg(
                    self.modrm_reg,
                    io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)? as u16 as u64,
                    self.opsize,
                );
            }
            0xBE => {
                // MOV and sign extend byte from mem (ModRM:r/m) to
                // reg (ModRM:reg).
                //
                // 0F BE/r		movsx r16, r/m8
                // 0F BE/r		movsx r32, r/m8
                // REX.W + 0F BE/r	movsx r64, r/m8
                self.update_gpreg(
                    self.modrm_reg,
                    io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)? as i8 as u64,
                    self.opsize,
                );
            }
            _ => {
                return Err(InstrEmulError::UnSupportedOpEmul(
                    self.op.optype,
                    self.op.opcode,
                ))
            }
        }

        Ok(())
    }

    fn emulate_pio(&mut self, io_op: &mut IoOperation) -> Result<(), InstrEmulError> {
        let repeat_count = if self.flags.contains(PrefixFlags::REPZ_P) {
            let rcx = self.ctx.get_gpreg(GuestCpuGPRegCode::Rcx);

            // The count register is depending on the address size of the
            // instruction.
            if rcx & self.addrsize.mask() == 0 {
                return Ok(());
            }
            Some(rcx)
        } else {
            None
        };

        let reg = if io_op.is_read() {
            // Write back pio-read-value to guest memory
            let gpa =
                self.get_opcode_addr_check(GuestCpuSegCode::ES, GuestCpuGPRegCode::Rdi, true)?;
            let val = io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)?;
            copy_to_gpa_addrsize(gpa, self.opsize, val).map_err(|e| {
                log::error!("Failed to copy PIO read data to guest memory: {:?}", e);
                InstrEmulError::BadEmul(self.op.optype, self.op.opcode)
            })?;
            GuestCpuGPRegCode::Rdi
        } else {
            // Read pio-write-data from guest memory
            let seg = self.override_seg.map_or(GuestCpuSegCode::DS, |s| s);
            let gpa = self.get_opcode_addr_check(seg, GuestCpuGPRegCode::Rsi, false)?;
            io_op.set_write_data(copy_from_gpa_addrsize(gpa, self.opsize).map_err(|e| {
                log::error!("Failed to copy PIO write data from guest memory: {:?}", e);
                InstrEmulError::BadEmul(self.op.optype, self.op.opcode)
            })?);
            GuestCpuGPRegCode::Rsi
        };

        //Update register with updated address
        let rflags = RFlags::from_bits_truncate(self.ctx.get_rflags());
        if rflags.contains(RFlags::DF) {
            self.update_gpreg(
                reg,
                self.ctx.get_gpreg(reg) - self.opsize as u8 as u64,
                self.addrsize,
            );
        } else {
            self.update_gpreg(
                reg,
                self.ctx.get_gpreg(reg) + self.opsize as u8 as u64,
                self.addrsize,
            );
        }

        if let Some(mut rcx) = repeat_count {
            // Update counter in RCX
            rcx -= 1;
            self.update_gpreg(GuestCpuGPRegCode::Rcx, rcx, self.addrsize);

            if rcx & self.addrsize.mask() != 0 {
                io_op.set_retry();
            }
        }

        Ok(())
    }

    fn emulate_stos(&mut self, io_op: &mut IoOperation) -> Result<(), InstrEmulError> {
        let repeat_count = if self.flags.contains(PrefixFlags::REPZ_P)
            | self.flags.contains(PrefixFlags::REPNZ_P)
        {
            let rcx = self.ctx.get_gpreg(GuestCpuGPRegCode::Rcx);

            // The count register is depending on the address size of the
            // instruction.
            if rcx & self.addrsize.mask() == 0 {
                return Ok(());
            }
            Some(rcx)
        } else {
            None
        };

        // Read write-data from guest RAX
        io_op.set_write_data(self.ctx.get_gpreg(GuestCpuGPRegCode::Rax));

        // Update registers
        let rflags = RFlags::from_bits_truncate(self.ctx.get_rflags());
        if rflags.contains(RFlags::DF) {
            self.update_gpreg(
                GuestCpuGPRegCode::Rdi,
                self.ctx.get_gpreg(GuestCpuGPRegCode::Rdi) - self.opsize as u8 as u64,
                self.addrsize,
            );
        } else {
            self.update_gpreg(
                GuestCpuGPRegCode::Rdi,
                self.ctx.get_gpreg(GuestCpuGPRegCode::Rdi) + self.opsize as u8 as u64,
                self.addrsize,
            );
        }

        if let Some(mut rcx) = repeat_count {
            // Update counter in RCX
            rcx -= 1;
            self.update_gpreg(GuestCpuGPRegCode::Rcx, rcx, self.addrsize);

            if rcx & self.addrsize.mask() != 0 {
                io_op.set_retry();
            }
        }

        Ok(())
    }

    fn emulate_sub(&mut self, io_op: &IoOperation) -> Result<(), InstrEmulError> {
        let (x, y) = match self.op.opcode {
            0x2B => {
                // SUB r/m from r and store the result in r
                //
                // 2B/r            SUB r16, r/m16
                // 2B/r            SUB r32, r/m32
                // REX.W + 2B/r    SUB r64, r/m64
                let val1 = self.ctx.get_gpreg(self.modrm_reg);
                let val2 = io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)?;

                self.update_gpreg(self.modrm_reg, val1 - val2, self.opsize);
                (val1, val2)
            }
            _ => {
                return Err(InstrEmulError::UnSupportedOpEmul(
                    self.op.optype,
                    self.op.opcode,
                ))
            }
        };

        let rflags = getcc(self.opsize, x, y);
        self.update_rflags(rflags.intersection(
            RFlags::CF | RFlags::PF | RFlags::AF | RFlags::ZF | RFlags::SF | RFlags::OF,
        ));

        Ok(())
    }

    fn emulate_test(&mut self, io_op: &IoOperation) -> Result<(), InstrEmulError> {
        let val = match self.op.opcode {
            0x84 | 0x85 => {
                // AND reg (ModRM:reg) and mem (ModRM:r/m) and discard
                // the result.
                //
                // 84/r		test r8, r/m8
                // 85/r		test r16, r/m16
                // 85/r		test r32, r/m32
                // REX.W + 85/r	test r64, r/m64
                let val1 = self.ctx.get_gpreg(self.modrm_reg);
                let val2 = io_op.get_read_data().ok_or(InstrEmulError::BadIOReq)?;
                val1 & val2
            }
            _ => {
                return Err(InstrEmulError::UnSupportedOpEmul(
                    self.op.optype,
                    self.op.opcode,
                ))
            }
        };

        // OF and CF are cleared; the SF, ZF and PF flags are set
        // according to the result; AF is undefined.
        //
        // The updated status flags are obtained by subtracting 0 from
        // 'result'.
        let rflags = getcc(self.opsize, val, 0);
        self.update_rflags(rflags.intersection(RFlags::PF | RFlags::ZF | RFlags::SF));

        Ok(())
    }

    fn dump_instr(&self) {
        log::info!(
            "Raw instruction code: {:x?}, OpType {:?}, OpFlags 0x{:x}",
            self.instr.code,
            self.op.optype,
            self.op.opflags
        );
    }

    pub fn emulate_instr(&mut self, io_op: &mut IoOperation) -> Result<(), TdxError> {
        match self.op.optype {
            OpType::And => self.emulate_and(io_op),
            OpType::BitTest => self.emulate_bittest(io_op),
            OpType::Cmp => self.emulate_cmp(io_op),
            OpType::Group1 => self.emulate_group1(io_op),
            OpType::Mov => self.emulate_mov(io_op),
            OpType::Movs => self.emulate_movs(io_op),
            OpType::Movsx | OpType::Movzx => self.emulate_movx(io_op),
            OpType::Pios => self.emulate_pio(io_op),
            OpType::Stos => self.emulate_stos(io_op),
            OpType::Sub => self.emulate_sub(io_op),
            OpType::Test => self.emulate_test(io_op),
            _ => Err(InstrEmulError::UnSupportedOpEmul(
                self.op.optype,
                self.op.opcode,
            )),
        }
        .map_err(|e| {
            log::error!("Failed to emulate instruction: {:?}", e);
            self.dump_instr();
            TdxError::from(e)
        })
    }
}
