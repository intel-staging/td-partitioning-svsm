// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::error::{ErrExcp, TdxError};
use super::gctx::{
    GuestCpuContext, GuestCpuGPRegCode, GuestCpuMode, GuestCpuRegCode, GuestCpuSegCode, Segment,
};
use super::gmem::{copy_from_gpa, gva2gpa, GuestMemAccessCode};
use super::ioreq::AddrSize;
use super::opcode::{OpCodeError, OpDesc, OpFlags, OpType};
use crate::address::GuestVirtAddr;
use crate::cpu::idt::common::PageFaultErrCode;

const INST_SIZE: usize = 15;
const PREFIX_SIZE: usize = 4;

#[derive(Debug)]
enum InstrEmulError {
    BadAddrSize,
    BadInstrLen,
    DecodeDisp,
    DecodeMOffset,
    DecodeModRM,
    DecodeOpCode(OpCodeError),
    DecodePrefix,
    GetRawInstr,
    InstrPeek,
    InjectExcp(ErrExcp),
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

#[allow(dead_code)]
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
}
