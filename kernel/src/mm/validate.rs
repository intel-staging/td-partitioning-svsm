// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::mm::alloc::{allocate_file_page_ref, allocate_pages, get_order};
use crate::mm::{virt_to_phys, PageRef};
use crate::types::{PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::{page_align_up, MemoryRegion};
use alloc::vec::Vec;
use core::cmp::min;
use core::ptr;

static VALID_BITMAP: SpinLock<ValidBitmap> = SpinLock::new(ValidBitmap::new());
// Number of u64's in one page
const PAGE_N64: usize = PAGE_SIZE / core::mem::size_of::<u64>();

#[inline(always)]
fn bitmap_bytes(region: MemoryRegion<PhysAddr>) -> usize {
    page_align_up(region.len().div_ceil(PAGE_SIZE).div_ceil(u8::BITS as usize))
}

#[inline(always)]
fn check_addr_range(
    region: MemoryRegion<PhysAddr>,
    paddr_begin: PhysAddr,
    paddr_end: PhysAddr,
) -> bool {
    if paddr_begin > paddr_end {
        false
    } else {
        paddr_begin >= region.start() && paddr_end <= region.end()
    }
}

pub fn init_valid_bitmap_ptr(region: MemoryRegion<PhysAddr>, bitmap: *mut u64) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.set_region(region);
    vb_ref.set_bitmap_ptr(bitmap);
}

pub fn init_valid_bitmap_alloc(region: MemoryRegion<PhysAddr>) -> Result<(), SvsmError> {
    let order: usize = get_order(bitmap_bytes(region));
    let bitmap_addr = allocate_pages(order)?;

    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.set_region(region);
    vb_ref.set_bitmap_ptr(bitmap_addr.as_mut_ptr::<u64>());
    vb_ref.clear_all();

    Ok(())
}

pub fn migrate_valid_bitmap() -> Result<(), SvsmError> {
    let mut page_refs = Vec::new();
    let page_count = VALID_BITMAP.lock().bitmap_npages();
    for _ in 0..page_count {
        page_refs.push(allocate_file_page_ref()?);
    }

    // lock again here because allocator path also takes VALID_BITMAP.lock()
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.migrate(page_refs);
    Ok(())
}

pub fn validated_phys_addr(paddr: PhysAddr) -> bool {
    let vb_ref = VALID_BITMAP.lock();
    vb_ref.is_valid_4k(paddr)
}

pub fn valid_bitmap_set_valid_4k(paddr: PhysAddr) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.set_valid_4k(paddr)
}

pub fn valid_bitmap_clear_valid_4k(paddr: PhysAddr) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.clear_valid_4k(paddr)
}

pub fn valid_bitmap_set_valid_2m(paddr: PhysAddr) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.set_valid_2m(paddr)
}

pub fn valid_bitmap_clear_valid_2m(paddr: PhysAddr) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.clear_valid_2m(paddr)
}

pub fn valid_bitmap_set_valid_range(paddr_begin: PhysAddr, paddr_end: PhysAddr) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.set_valid_range(paddr_begin, paddr_end);
}

pub fn valid_bitmap_clear_valid_range(paddr_begin: PhysAddr, paddr_end: PhysAddr) {
    let mut vb_ref = VALID_BITMAP.lock();
    vb_ref.clear_valid_range(paddr_begin, paddr_end);
}

pub fn valid_bitmap_addr() -> PhysAddr {
    let vb_ref = VALID_BITMAP.lock();
    vb_ref.bitmap_addr()
}

pub fn valid_bitmap_valid_page(paddr: PhysAddr) -> bool {
    let vb_ref = VALID_BITMAP.lock();
    vb_ref.check_page(paddr)
}

#[derive(Debug)]
enum ValidBitmapMem {
    Ptr(*mut u64),
    PageRefs(Vec<PageRef>),
}

#[derive(Debug)]
struct ValidBitmap {
    region: MemoryRegion<PhysAddr>,
    bitmap: Option<ValidBitmapMem>,
}

impl ValidBitmap {
    const fn new() -> Self {
        ValidBitmap {
            region: MemoryRegion::from_addresses(PhysAddr::null(), PhysAddr::null()),
            bitmap: None,
        }
    }

    fn set_region(&mut self, region: MemoryRegion<PhysAddr>) {
        self.region = region;
    }

    fn set_bitmap_ptr(&mut self, bitmap: *mut u64) {
        if bitmap.is_null() {
            return;
        }
        self.bitmap = Some(ValidBitmapMem::Ptr(bitmap));
    }

    fn set_bitmap_page_refs(&mut self, page_refs: Vec<PageRef>) {
        if page_refs.is_empty() {
            return;
        }
        self.bitmap = Some(ValidBitmapMem::PageRefs(page_refs));
    }

    fn check_addr_range(&self, paddr_begin: PhysAddr, paddr_end: PhysAddr) -> bool {
        check_addr_range(self.region, paddr_begin, paddr_end)
    }

    #[inline(always)]
    fn check_page(&self, paddr: PhysAddr) -> bool {
        self.check_addr_range(paddr, paddr + PAGE_SIZE)
    }

    #[inline(always)]
    fn check_page_2m(&self, paddr: PhysAddr) -> bool {
        self.check_addr_range(paddr, paddr + PAGE_SIZE_2M)
    }

    fn bitmap_addr(&self) -> PhysAddr {
        assert!(self.bitmap.is_some());
        let Some(bitmap) = &self.bitmap else {
            panic!("ValidBitmap bitmap is none");
        };

        match bitmap {
            ValidBitmapMem::Ptr(ptr) => virt_to_phys(VirtAddr::from(*ptr)),
            _ => PhysAddr::null(),
        }
    }

    #[inline(always)]
    fn index(&self, paddr: PhysAddr) -> (usize, usize) {
        let page_offset = (paddr - self.region.start()) / PAGE_SIZE;
        let index = page_offset / u64::BITS as usize;
        let bit = page_offset % u64::BITS as usize;

        (index, bit)
    }

    fn clear_all(&mut self) {
        let len = self.bitmap_len();

        if let Some(bitmap) = &mut self.bitmap {
            match bitmap {
                ValidBitmapMem::Ptr(ptr) => unsafe {
                    ptr::write_bytes(*ptr, 0, len);
                },
                ValidBitmapMem::PageRefs(pr) => {
                    for page_ref in pr.iter_mut() {
                        unsafe {
                            let ptr = page_ref.as_mut() as *mut [u8; PAGE_SIZE] as *mut u64;
                            ptr::write_bytes(ptr, 0, PAGE_N64);
                        }
                    }
                }
            }
        }
    }

    fn bitmap_npages(&self) -> usize {
        bitmap_bytes(self.region) / PAGE_SIZE
    }

    /// The number of u64's in the bitmap
    fn bitmap_len(&self) -> usize {
        self.bitmap_npages() * PAGE_N64
    }

    fn migrate(&mut self, mut page_refs: Vec<PageRef>) {
        let mut count = self.bitmap_len();
        if let Some(bitmap) = &mut self.bitmap {
            match bitmap {
                ValidBitmapMem::Ptr(ptr) => {
                    for (i, page_ref) in page_refs.iter_mut().enumerate() {
                        let src = ptr.wrapping_add(i * PAGE_N64);
                        let len = min(count, PAGE_N64);
                        unsafe {
                            let dst = page_ref.as_mut() as *mut [u8; PAGE_SIZE] as *mut u64;
                            if len > 0 {
                                ptr::copy_nonoverlapping(src, dst, len);
                            }
                            // Zero out any unused u64's
                            if len < PAGE_N64 {
                                let dst = dst.wrapping_add(len);
                                ptr::write_bytes(dst, 0, PAGE_N64 - len);
                            }
                        }
                        count -= len;
                    }
                }
                ValidBitmapMem::PageRefs(pr) => {
                    let src_pr = pr.as_slice();
                    let dst_pr = page_refs.as_mut_slice();

                    for i in 0..pr.len() {
                        unsafe {
                            let src = src_pr[i].as_ref() as *const [u8; PAGE_SIZE] as *const u64;
                            let dst = dst_pr[i].as_mut() as *mut [u8; PAGE_SIZE] as *mut u64;
                            ptr::copy_nonoverlapping(src, dst, PAGE_N64);
                        }
                    }
                }
            }
        }

        self.set_bitmap_page_refs(page_refs);
    }

    fn initialized(&self) -> bool {
        self.bitmap.is_some()
    }

    fn read_bitmap_u64(&self, index: usize) -> u64 {
        if let Some(bitmap) = &self.bitmap {
            match bitmap {
                ValidBitmapMem::Ptr(ptr) => unsafe { ptr::read(ptr.add(index)) },
                ValidBitmapMem::PageRefs(pr) => {
                    let page_refs = pr.as_slice();
                    let (idx, off) = (index / PAGE_N64, index % PAGE_N64);
                    unsafe {
                        let ptr = page_refs[idx].as_ref() as *const [u8; PAGE_SIZE] as *const u64;
                        ptr::read(ptr.add(off))
                    }
                }
            }
        } else {
            unreachable!("ValidBitmap: No bitmap initialized");
        }
    }

    fn write_bitmap_u64(&mut self, index: usize, val: u64) {
        if let Some(bitmap) = &mut self.bitmap {
            match bitmap {
                ValidBitmapMem::Ptr(ptr) => unsafe {
                    ptr::write(ptr.add(index), val);
                },
                ValidBitmapMem::PageRefs(pr) => {
                    let page_refs = pr.as_mut_slice();
                    let (idx, off) = (index / PAGE_N64, index % PAGE_N64);
                    unsafe {
                        let ptr = page_refs[idx].as_mut() as *mut [u8; PAGE_SIZE] as *mut u64;
                        ptr::write(ptr.add(off), val);
                    }
                }
            }
        } else {
            unreachable!("ValidBitmap: No bitmap initialized");
        }
    }

    fn set_valid_4k(&mut self, paddr: PhysAddr) {
        if !self.initialized() {
            return;
        }

        let (index, bit) = self.index(paddr);

        assert!(paddr.is_page_aligned());
        assert!(self.check_page(paddr));

        let val = self.read_bitmap_u64(index) | (1u64 << bit);
        self.write_bitmap_u64(index, val);
    }

    fn clear_valid_4k(&mut self, paddr: PhysAddr) {
        if !self.initialized() {
            return;
        }

        let (index, bit) = self.index(paddr);

        assert!(paddr.is_page_aligned());
        assert!(self.check_page(paddr));

        let val = self.read_bitmap_u64(index) & !(1u64 << bit);
        self.write_bitmap_u64(index, val);
    }

    fn set_2m(&mut self, paddr: PhysAddr, val: u64) {
        if !self.initialized() {
            return;
        }

        const NR_INDEX: usize = PAGE_SIZE_2M / (PAGE_SIZE * u64::BITS as usize);
        let (index, _) = self.index(paddr);

        assert!(paddr.is_aligned(PAGE_SIZE_2M));
        assert!(self.check_page_2m(paddr));

        for i in 0..NR_INDEX {
            self.write_bitmap_u64(index + i, val);
        }
    }

    fn set_valid_2m(&mut self, paddr: PhysAddr) {
        self.set_2m(paddr, !0u64);
    }

    fn clear_valid_2m(&mut self, paddr: PhysAddr) {
        self.set_2m(paddr, 0u64);
    }

    fn modify_bitmap_word(&mut self, index: usize, mask: u64, new_val: u64) {
        let val = self.read_bitmap_u64(index);
        let val = (val & !mask) | (new_val & mask);
        self.write_bitmap_u64(index, val);
    }

    fn set_range(&mut self, paddr_begin: PhysAddr, paddr_end: PhysAddr, new_val: bool) {
        if !self.initialized() {
            return;
        }

        // All ones.
        let mask = !0u64;
        // All ones if val == true, zero otherwise.
        let new_val = 0u64.wrapping_sub(new_val as u64);

        let (index_head, bit_head_begin) = self.index(paddr_begin);
        let (index_tail, bit_tail_end) = self.index(paddr_end);
        if index_head != index_tail {
            let mask_head = mask >> bit_head_begin << bit_head_begin;
            self.modify_bitmap_word(index_head, mask_head, new_val);

            for index in (index_head + 1)..index_tail {
                self.write_bitmap_u64(index, new_val);
            }

            if bit_tail_end != 0 {
                let mask_tail = mask << (64 - bit_tail_end) >> (64 - bit_tail_end);
                self.modify_bitmap_word(index_tail, mask_tail, new_val);
            }
        } else {
            let mask = mask >> bit_head_begin << bit_head_begin;
            let mask = mask << (64 - bit_tail_end) >> (64 - bit_tail_end);
            self.modify_bitmap_word(index_head, mask, new_val);
        }
    }

    fn set_valid_range(&mut self, paddr_begin: PhysAddr, paddr_end: PhysAddr) {
        self.set_range(paddr_begin, paddr_end, true);
    }

    fn clear_valid_range(&mut self, paddr_begin: PhysAddr, paddr_end: PhysAddr) {
        self.set_range(paddr_begin, paddr_end, false);
    }

    fn is_valid_4k(&self, paddr: PhysAddr) -> bool {
        if !self.initialized() {
            return false;
        }

        let (index, bit) = self.index(paddr);

        assert!(self.check_page(paddr));

        let mask = 1u64 << bit;
        let val = self.read_bitmap_u64(index);
        (val & mask) == mask
    }
}

unsafe impl Send for ValidBitmap {}
