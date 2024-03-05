// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, VirtAddr};
use core::arch::asm;

const INVLPGB_VALID_VA: u64 = 1u64 << 0;
//const INVLPGB_VALID_PCID: u64 = 1u64 << 1;
const INVLPGB_VALID_ASID: u64 = 1u64 << 2;
const INVLPGB_VALID_GLOBAL: u64 = 1u64 << 3;

#[inline]
fn do_invlpgb(rax: u64, rcx: u64, rdx: u64) {
    unsafe {
        asm!(".byte 0x0f, 0x01, 0xfe",
             in("rax") rax,
             in("rcx") rcx,
             in("rdx") rdx,
             options(att_syntax));
    }
}

#[inline]
fn do_tlbsync() {
    unsafe {
        asm!(".byte 0x0f, 0x01, 0xff", options(att_syntax));
    }
}

#[allow(unreachable_code, unused)]
pub fn flush_tlb() {
    panic!("flush_tlb not supported");
    let rax: u64 = INVLPGB_VALID_ASID;
    do_invlpgb(rax, 0, 0);
}

#[allow(unreachable_code, unused)]
pub fn flush_tlb_sync() {
    panic!("flush_tlb_sync not supported");
    flush_tlb();
    do_tlbsync();
}

#[allow(unreachable_code, unused)]
pub fn flush_tlb_global() {
    panic!("flush_tlb_global not supported");
    let rax: u64 = INVLPGB_VALID_ASID | INVLPGB_VALID_GLOBAL;
    do_invlpgb(rax, 0, 0);
}

#[allow(unreachable_code, unused)]
pub fn flush_tlb_global_sync() {
    panic!("flush_tlb_global_sync not supported");
    flush_tlb_global();
    do_tlbsync();
}

#[allow(unreachable_code, unused)]
pub fn flush_address(va: VirtAddr) {
    panic!("flush_address not supported");
    let rax: u64 = (va.page_align().bits() as u64)
        | INVLPGB_VALID_VA
        | INVLPGB_VALID_ASID
        | INVLPGB_VALID_GLOBAL;
    do_invlpgb(rax, 0, 0);
}

#[allow(unreachable_code, unused)]
pub fn flush_address_sync(va: VirtAddr) {
    panic!("flush_address_sync not supported");
    flush_address(va);
    do_tlbsync();
}

// copied from x86_64::instructions::tlb::flush
#[inline]
pub fn flush_address_local(va: VirtAddr) {
    unsafe {
        asm!("invlpg [{}]",
             in(reg) va.page_align().bits() as u64,
             options(nostack, preserves_flags));
    }
}
