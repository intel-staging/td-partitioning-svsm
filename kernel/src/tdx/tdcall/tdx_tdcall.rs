// Copyright (c) 2020-2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Implemention of a subset of TDCALL functions defined in Intel TDX Module v1.0 and v1.5
//! Spec and TDVMCALL sub-functions defined in TDX GHCI Spec.
//!
//! The TDCALL instruction causes a VM exit to the Intel TDX Module. It is used to call
//! guest-side Intel TDX functions, either local or a TD exit to the host VMM.
//!
//! TDVMCALL (TDG.VP.VMCALL) is a leaf function 0 for TDCALL. It helps invoke services from
//! the host VMM.

use super::*;
use core::arch::asm;
use core::result::Result;
use core::sync::atomic::{fence, Ordering};
use lazy_static::lazy_static;

const IO_READ: u64 = 0;
const IO_WRITE: u64 = 1;
const PAGE_SIZE_4K: u64 = 4 * 1024;
const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;

/// SHA384 digest value extended to RTMR
/// Both alignment and size are 64 bytes.
#[repr(C, align(64))]
pub struct TdxDigest {
    pub data: [u8; 48],
}

/// Guest TD execution evironment returned from TDG.VP.INFO leaf
#[repr(C)]
#[derive(Debug, Default)]
pub struct TdInfo {
    pub gpaw: u64,
    pub attributes: u64,
    pub max_vcpus: u32,
    pub num_vcpus: u32,
    pub vcpu_index: u32,
    pub rsvd: [u32; 5],
}

/// Virtualization exception information returned from TDG.VP.VEINFO.GET leaf
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct TdVeInfo {
    pub exit_reason: u32,
    pub rsvd: u32,
    pub exit_qualification: u64,
    pub guest_la: u64,
    pub guest_pa: u64,
    pub exit_instruction_length: u32,
    pub exit_instruction_info: u32,
    pub rsvd1: u64,
}

/// Emulated CPUID values returned from TDG.VP.VMCALL<Instruction.CPUID>
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct CpuIdInfo {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

lazy_static! {
    static ref SHARED_MASK: u64 = td_shared_mask().expect("Fail to get the shared mask of TD");
}

/// Used to help perform HLT operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.HLT>'
pub fn tdvmcall_halt() {
    let rflags: u64;
    unsafe {
        asm!("pushfq; pop {}", out(reg) rflags, options(nomem, preserves_flags));
    }

    let interrupt_blocked = if rflags & 0x200 == 0 { 1 } else { 0 };

    let mut args = TdVmcallArgs {
        r11: TDVMCALL_HALT,
        r12: interrupt_blocked as u64,
        ..Default::default()
    };

    let _ = td_vmcall(&mut args);
}

/// Executing `hlt` instruction will cause a #VE to emulate the instruction. Safe halt operation
/// `sti;hlt` which typically used for idle is not working in this case since `hlt` instruction
/// must be the instruction next to `sti`. To use safe halt, `sti` must be executed just before
/// `tdcall` instruction.
pub fn tdvmcall_sti_halt() {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_HALT,
        ..Default::default()
    };

    // Set the `do_sti` flag to execute `sti` before `tdcall` instruction
    // Result is always `TDG.VP.VMCALL_SUCCESS`
    let _ = td_vmcall_ex(&mut args, true);
}

/// Request the VMM perform single byte IO read operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn tdvmcall_io_read_8(port: u16) -> u8 {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u8>() as u64,
        r13: IO_READ,
        r14: port as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }

    (args.r11 & 0xff) as u8
}

/// Request the VMM perform 2-bytes byte IO read operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn tdvmcall_io_read_16(port: u16) -> u16 {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u16>() as u64,
        r13: IO_READ,
        r14: port as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }

    (args.r11 & 0xffff) as u16
}

/// Request the VMM perform 4-bytes byte IO read operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn tdvmcall_io_read_32(port: u16) -> u32 {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u32>() as u64,
        r13: IO_READ,
        r14: port as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }

    (args.r11 & 0xffff_ffff) as u32
}

/// Request the VMM perform single byte IO write operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn tdvmcall_io_write_8(port: u16, byte: u8) {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u8>() as u64,
        r13: IO_WRITE,
        r14: port as u64,
        r15: byte as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
}

/// Request the VMM perform 2-bytes IO write operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn tdvmcall_io_write_16(port: u16, byte: u16) {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u16>() as u64,
        r13: IO_WRITE,
        r14: port as u64,
        r15: byte as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
}

/// Request the VMM perform 4-bytes IO write operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn tdvmcall_io_write_32(port: u16, byte: u32) {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u32>() as u64,
        r13: IO_WRITE,
        r14: port as u64,
        r15: byte as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
}

/// Used to help request the VMM perform emulated-MMIO-write operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<#VE.RequestMMIO>'
pub fn tdvmcall_mmio_write<T: Sized>(address: *const T, value: T) {
    let address = address as u64 | *SHARED_MASK;
    fence(Ordering::SeqCst);
    let val = unsafe { *(core::ptr::addr_of!(value) as *const u64) };

    let mut args = TdVmcallArgs {
        r11: TDVMCALL_MMIO,
        r12: core::mem::size_of::<T>() as u64,
        r13: IO_WRITE,
        r14: address,
        r15: val,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
}

/// Used to help request the VMM perform emulated-MMIO-read operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<#VE.RequestMMIO>'
pub fn tdvmcall_mmio_read<T: Clone + Copy + Sized>(address: usize) -> T {
    let address = address as u64 | *SHARED_MASK;
    fence(Ordering::SeqCst);

    let mut args = TdVmcallArgs {
        r11: TDVMCALL_MMIO,
        r12: core::mem::size_of::<T>() as u64,
        r13: IO_READ,
        r14: address,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }

    unsafe { *(core::ptr::addr_of!(args.r11) as *const T) }
}

/// Used to request the host VMM to map a GPA range as a private or shared memory mappings.
/// It can be used to convert page mappings from private to shared or vice versa
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<MapGPA>'
pub fn tdvmcall_mapgpa(shared: bool, paddr: u64, length: usize) -> Result<(), TdVmcallError> {
    let share_bit = *SHARED_MASK;
    let mut paddr_start = if shared {
        paddr | share_bit
    } else {
        paddr & (!share_bit)
    };
    let mut remain_len = length as u64;

    loop {
        let mut args = TdVmcallArgs {
            r11: TDVMCALL_MAPGPA,
            r12: paddr_start,
            r13: remain_len,
            ..Default::default()
        };

        let ret = td_vmcall(&mut args);

        if ret == TDVMCALL_STATUS_SUCCESS {
            break;
        }

        match ret.into() {
            TdVmcallError::VmcallRetry => {
                remain_len -= args.r11 - paddr_start;
                paddr_start = args.r11;
            }
            _ => return Err(ret.into()),
        }
    }

    log::trace!(
        "tdvmcall mapgpa - paddr: {:x}, length: {:x}\n",
        paddr,
        length
    );

    Ok(())
}

/// Used to help perform RDMSR operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.RDMSR>'
pub fn tdvmcall_rdmsr(index: u32) -> Result<u64, TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_RDMSR,
        r12: index as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(args.r11)
}

/// Used to help perform WRMSR operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.WRMSR>'
pub fn tdvmcall_wrmsr(index: u32, value: u64) -> Result<(), TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_WRMSR,
        r12: index as u64,
        r13: value,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(())
}

/// Used to enable the TD-guest to request the VMM to emulate the CPUID operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.WRMSR>'
pub fn tdvmcall_cpuid(eax: u32, ecx: u32) -> CpuIdInfo {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_CPUID,
        r12: eax as u64,
        r13: ecx as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }

    CpuIdInfo {
        eax: (args.r12 & 0xffff_ffff) as u32,
        ebx: (args.r13 & 0xffff_ffff) as u32,
        ecx: (args.r14 & 0xffff_ffff) as u32,
        edx: (args.r15 & 0xffff_ffff) as u32,
    }
}

/// Used to request the host VMM specify which interrupt vector to use as an event-notify
/// vector.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<SetupEventNotifyInterrupt>'
pub fn tdvmcall_setup_event_notify(vector: u64) -> Result<(), TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_SETUPEVENTNOTIFY,
        r12: vector,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(())
}

/// Used to invoke a request to generate a TD-Quote signing by a TD-Quoting Enclave
/// operating in the host environment.
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<GetQuote>'
///
/// * buffer: a piece of 4KB-aligned shared memory
pub fn tdvmcall_get_quote(buffer: u64, size: u64) -> Result<(), TdVmcallError> {
    let addr = buffer | *SHARED_MASK;

    let mut args = TdVmcallArgs {
        r11: TDVMCALL_GETQUOTE,
        r12: addr,
        r13: size,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(())
}

/// Get guest TD execution environment information
///
/// Details can be found in TDX Module ABI spec section 'TDG.VP.INFO Leaf'
pub fn tdcall_get_td_info() -> Result<TdInfo, TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_TDINFO,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    let td_info = TdInfo {
        gpaw: args.rcx & 0x3f,
        attributes: args.rdx,
        max_vcpus: (args.r8 >> 32) as u32,
        num_vcpus: args.r8 as u32,
        vcpu_index: args.r9 as u32,
        ..Default::default()
    };

    Ok(td_info)
}

/// Extend a TDCS.RTMR measurement register
///
/// Details can be found in TDX Module ABI spec section 'TDG.VP.INFO Leaf'
pub fn tdcall_extend_rtmr(digest: &TdxDigest, mr_index: u32) -> Result<(), TdCallError> {
    let buffer: u64 = core::ptr::addr_of!(digest.data) as u64;

    let mut args = TdcallArgs {
        rax: TDCALL_TDEXTENDRTMR,
        rcx: buffer,
        rdx: mr_index as u64,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(())
}

/// Get virtualization exception information for the recent #VE
///
/// Details can be found in TDX Module ABI spec section 'TDG.VP.VEINFO.GET Leaf'
pub fn tdcall_get_ve_info() -> Result<TdVeInfo, TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_TDGETVEINFO,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    let ve_info = TdVeInfo {
        exit_reason: args.rcx as u32,
        exit_qualification: args.rdx,
        guest_la: args.r8,
        guest_pa: args.r9,
        exit_instruction_length: args.r10 as u32,
        exit_instruction_info: (args.r10 >> 32) as u32,
        ..Default::default()
    };

    Ok(ve_info)
}

/// Accept a pending private page, and initialize the page to zeros using the TD ephemeral
/// private key
///
/// Details can be found in TDX Module ABI spec section 'TDG.MEM.PAGE.Accept Leaf'
pub fn tdcall_accept_page(address: u64) -> Result<(), TdCallError> {
    let mut retry = 0u32;
    loop {
        let mut args = TdcallArgs {
            rax: TDCALL_TDACCEPTPAGE,
            rcx: address,
            ..Default::default()
        };
        let ret = td_call(&mut args);
        match ret {
            TDCALL_STATUS_SUCCESS => return Ok(()),
            TDCALL_STATUS_OPERAND_BUSY => {
                if {
                    retry += 1;
                    retry
                } > TDCALL_ACCEPTPAGE_MAX_RETRY
                {
                    return Err(ret.into());
                } else {
                    continue;
                }
            }
            _ => return Err(ret.into()),
        }
    }
}

fn td_accept_pages(address: u64, pages: u64, page_size: u64) {
    for i in 0..pages {
        let accept_addr = address + i * page_size;
        let accept_level = if page_size == PAGE_SIZE_2M { 1 } else { 0 };
        match tdcall_accept_page(accept_addr | accept_level) {
            Ok(()) => {}
            Err(e) => {
                if let TdCallError::LeafSpecific(error_code) = e {
                    if error_code == TDCALL_STATUS_PAGE_SIZE_MISMATCH {
                        if page_size == PAGE_SIZE_2M {
                            td_accept_pages(accept_addr, 512, PAGE_SIZE_4K);
                            continue;
                        }
                    } else if error_code == TDCALL_STATUS_PAGE_ALREADY_ACCEPTED {
                        continue;
                    }
                }
                panic!(
                    "Accept Page Error: 0x{:x}, page_size: {}, err {:?}\n",
                    accept_addr, page_size, e
                );
            }
        }
    }
}

pub fn td_accept_memory(address: u64, len: u64) {
    let mut start = address;
    let end = address + len;

    while start < end {
        let remaining = end - start;

        if remaining >= PAGE_SIZE_2M && (start & (PAGE_SIZE_2M - 1)) == 0 {
            let npages = remaining >> 21;
            td_accept_pages(start, npages, PAGE_SIZE_2M);
            start += npages << 21;
        } else if remaining >= PAGE_SIZE_4K && (start & (PAGE_SIZE_4K - 1)) == 0 {
            td_accept_pages(start, 1, PAGE_SIZE_4K);
            start += PAGE_SIZE_4K;
        } else {
            panic!("Accept Memory Error: 0x{:x}, length: {}\n", address, len);
        }
    }
}

/// Get the guest physical address (GPA) width via TDG.VP.INFO
/// The GPA width can be used to determine the shared-bit of GPA
pub fn td_shared_mask() -> Option<u64> {
    let td_info = tdcall_get_td_info().ok()?;
    let gpaw = (td_info.gpaw & 0x3f) as u8;

    // Detail can be found in TDX Module v1.5 ABI spec section 'TDVPS(excluding TD VMCS)'.
    if gpaw == 48 || gpaw == 52 {
        Some(1u64 << (gpaw - 1))
    } else {
        None
    }
}

pub fn tdcall_vp_read(field: u64) -> Result<u64, TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_VP_RD,
        rdx: field,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(args.r8)
}

pub fn tdcall_vp_write(field: u64, value: u64, mask: u64) -> Result<(), TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_VP_WR,
        rdx: field,
        r8: value,
        r9: mask,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(())
}

pub fn tdcall_vm_read(field: u64) -> Result<u64, TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_VM_RD,
        rdx: field,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(args.r8)
}

pub fn tdcall_vm_write(field: u64, value: u64, mask: u64) -> Result<(), TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_VM_WR,
        rdx: field,
        r8: value,
        r9: mask,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(())
}

pub fn tdcall_vp_invvpid(flags: u64, gla: u64) -> Result<u64, TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_VP_INVVPID,
        rcx: flags,
        rdx: gla,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(ret)
}

pub fn tdcall_vp_invept(vm_flags: u64) -> Result<u64, TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_VP_INVEPT,
        rcx: vm_flags,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(ret)
}

pub fn tdcall_vp_enter(vm_flags: u64, gpa: u64) -> TdcallArgs {
    let mut args = TdcallArgs {
        rax: TDCALL_VP_ENTER,
        rcx: vm_flags,
        rdx: gpa,
        ..Default::default()
    };

    let _ = td_call(&mut args);

    args
}

pub fn tdvmcall_share_irte_hdr(
    paddr: u64,
    vm_idx: u64,
    num_shared_pages: u64,
) -> Result<(), TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_SHARED_IRTE_HDR,
        r12: paddr,
        r13: vm_idx,
        r14: num_shared_pages,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(())
}

pub fn tdcall_mem_page_attr_wr(
    gpa_mapping: u64,
    gpa_attr: u64,
    attr_flags: u64,
) -> Result<u64, TdCallError> {
    loop {
        let mut args = TdcallArgs {
            rax: TDCALL_MEM_PAGE_ATTR_WR,
            rcx: gpa_mapping,
            rdx: gpa_attr,
            r8: attr_flags,
            ..Default::default()
        };

        let ret = td_call(&mut args);

        if ret != TDCALL_STATUS_SUCCESS {
            let err = ret.into();
            match err {
                TdCallError::TdxExitReasonOperandBusy => continue,
                _ => return Err(err),
            }
        }

        return Ok(args.rdx);
    }
}
