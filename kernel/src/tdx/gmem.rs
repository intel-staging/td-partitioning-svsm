// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

extern crate alloc;

use super::error::TdxError;
use super::gctx::GuestCpuContext;
use super::tdcall::{td_accept_memory, tdvmcall_mapgpa};
use super::utils::td_convert_guest_pages;
use crate::address::{Address, GuestPhysAddr, GuestVirtAddr};
use crate::cpu::control_regs::{CR0Flags, CR4Flags};
use crate::cpu::efer::EFERFlags;
use crate::cpu::registers::RFlags;
use crate::locking::RWLock;
use crate::mm::alloc::allocate_file_page_ref;
use crate::mm::guestmem::GuestMemMap;
use crate::mm::memory::{get_memory_map, is_guest_phys_addr_valid};
use crate::mm::pagetable::PTEntryFlags;
use crate::mm::ptguards::PerCPUPageMappingGuard;
use crate::mm::validate::{AtomicValidBitmap, ValidBitmap};
use crate::types::PAGE_SIZE;
use crate::utils::{immut_after_init::ImmutAfterInitCell, MemoryRegion};
use alloc::vec::Vec;
use bitflags::bitflags;
use core::mem::size_of;
use core::ops::Index;

#[derive(Debug)]
struct GuestMemBitmap {
    accepted: AtomicValidBitmap,
    shared: ValidBitmap,
}

impl GuestMemBitmap {
    fn new(gpa_start: GuestPhysAddr, gpa_end: GuestPhysAddr) -> Self {
        let hpa_start = gpa_start.page_align().to_host_phys_addr();
        let hpa_end = gpa_end.page_align_up().to_host_phys_addr();

        // Create empty accepted bitmap
        let mut accepted_bitmap = AtomicValidBitmap::new();
        accepted_bitmap.set_region(MemoryRegion::new(hpa_start, hpa_end - hpa_start));
        let page_count = accepted_bitmap.bitmap_npages();
        let mut page_refs = Vec::new();
        for _ in 0..page_count {
            page_refs.push(
                allocate_file_page_ref().expect("No enough memory to allocate accept bitmap"),
            );
        }
        accepted_bitmap.set_bitmap(page_refs);
        accepted_bitmap.clear_all();

        // Create empty shared bitmap
        let mut shared_bitmap = ValidBitmap::new();
        shared_bitmap.set_region(MemoryRegion::new(hpa_start, hpa_end - hpa_start));
        let mut page_refs = Vec::new();
        // Two bitmaps have the same region range and length
        for _ in 0..page_count {
            page_refs.push(
                allocate_file_page_ref().expect("No enough memory to allocate shared bitmap"),
            );
        }
        shared_bitmap.set_bitmap_page_refs(page_refs);
        // Convert all guest memory region to private.
        tdvmcall_mapgpa(false, u64::from(hpa_start), hpa_end - hpa_start)
            .expect("Failed to convert guest memory to private");
        shared_bitmap.clear_all();

        GuestMemBitmap {
            accepted: accepted_bitmap,
            shared: shared_bitmap,
        }
    }

    fn set_accepted_bitmap(
        &self,
        gpa_start: GuestPhysAddr,
        gpa_end: GuestPhysAddr,
    ) -> Result<usize, TdxError> {
        let hpa_start = gpa_start.page_align().to_host_phys_addr();
        let hpa_end = gpa_end.page_align_up().to_host_phys_addr();

        if !self.accepted.check_addr_range(hpa_start, hpa_end) {
            return Ok(0);
        }

        // Not to accept the page shared by TDP guest. Such page
        // should be accepted by clear_shared_bitmap.
        if !self.shared.is_invalid_range(hpa_start, hpa_end) {
            return Err(TdxError::PageAccept);
        }

        // Accept memory if the accept bitmap is not valid
        // (not all 1)
        if !self.accepted.is_valid_range(hpa_start, hpa_end) {
            td_accept_memory(u64::from(hpa_start), (hpa_end - hpa_start) as u64);
            self.accepted.set_valid_range(hpa_start, hpa_end);
        }

        Ok(hpa_end - hpa_start)
    }

    fn set_shared_bitmap(
        &mut self,
        gpa_start: GuestPhysAddr,
        gpa_end: GuestPhysAddr,
    ) -> Result<usize, TdxError> {
        let hpa_start = gpa_start.page_align().to_host_phys_addr();
        let hpa_end = gpa_end.page_align_up().to_host_phys_addr();

        if !self.shared.check_addr_range(hpa_start, hpa_end) {
            return Ok(0);
        }

        // Convert memory to shared if the shared bitmap
        // is not valid (not all 1)
        if !self.shared.is_valid_range(hpa_start, hpa_end) {
            td_convert_guest_pages(gpa_start, gpa_end, true)?;
            self.shared.set_valid_range(hpa_start, hpa_end);
            self.accepted.clear_valid_range(hpa_start, hpa_end);
        }

        Ok(hpa_end - hpa_start)
    }

    fn clear_shared_bitmap(
        &mut self,
        gpa_start: GuestPhysAddr,
        gpa_end: GuestPhysAddr,
    ) -> Result<usize, TdxError> {
        let hpa_start = gpa_start.page_align().to_host_phys_addr();
        let hpa_end = gpa_end.page_align_up().to_host_phys_addr();

        if !self.shared.check_addr_range(hpa_start, hpa_end) {
            return Ok(0);
        }

        // Convert memory to private if the shared bitmap
        // is not invalid (not all 0)
        if !self.shared.is_invalid_range(hpa_start, hpa_end) {
            td_convert_guest_pages(gpa_start, gpa_end, false)?;
            self.shared.clear_valid_range(hpa_start, hpa_end);
            self.accepted.set_valid_range(hpa_start, hpa_end);
        }

        Ok(hpa_end - hpa_start)
    }
}

#[derive(Debug)]
struct GuestMemBitmaps {
    bitmaps: Vec<RWLock<GuestMemBitmap>>,
}

static GMEM_BITMAPS: ImmutAfterInitCell<RWLock<Option<GuestMemBitmaps>>> =
    ImmutAfterInitCell::new(RWLock::new(None));

impl GuestMemBitmaps {
    fn new() -> Self {
        let mr = get_memory_map();
        let mut bitmaps = Vec::new();

        for r in mr.iter() {
            bitmaps.push(RWLock::new(GuestMemBitmap::new(r.start(), r.end())));
        }

        GuestMemBitmaps { bitmaps }
    }

    fn set_accepted_bitmap(
        &self,
        gpa_start: GuestPhysAddr,
        gpa_end: GuestPhysAddr,
    ) -> Result<usize, TdxError> {
        for bitmap in self.bitmaps.iter() {
            let len = bitmap.lock_read().set_accepted_bitmap(gpa_start, gpa_end)?;
            if len == (gpa_end - gpa_start) {
                return Ok(len);
            }
        }

        // Not found in memory region, probably is guest ROM
        Ok(0)
    }

    fn set_shared_bitmap(
        &self,
        gpa_start: GuestPhysAddr,
        gpa_end: GuestPhysAddr,
    ) -> Result<usize, TdxError> {
        for bitmap in self.bitmaps.iter() {
            let len = bitmap.lock_write().set_shared_bitmap(gpa_start, gpa_end)?;
            if len == (gpa_end - gpa_start) {
                return Ok(len);
            }
        }

        // Not found in memory region, probably is guest ROM
        Ok(0)
    }

    fn clear_shared_bitmap(
        &self,
        gpa_start: GuestPhysAddr,
        gpa_end: GuestPhysAddr,
    ) -> Result<usize, TdxError> {
        for bitmap in self.bitmaps.iter() {
            let len = bitmap
                .lock_write()
                .clear_shared_bitmap(gpa_start, gpa_end)?;
            if len == (gpa_end - gpa_start) {
                return Ok(len);
            }
        }

        // Not found in memory region, probably is guest ROM
        Ok(0)
    }
}

fn init_gmem_bitmaps() {
    let mut bitmaps = GMEM_BITMAPS.lock_write();
    // GMEM_BITMAPS may already be initialized by another CPU.
    // So do nothing if bitmaps is Some().
    if bitmaps.is_none() {
        *bitmaps = Some(GuestMemBitmaps::new());
    }
}

fn set_accepted_bitmap(
    gpa_start: GuestPhysAddr,
    gpa_end: GuestPhysAddr,
) -> Option<Result<usize, TdxError>> {
    GMEM_BITMAPS
        .lock_read()
        .as_ref()
        .map(|bitmaps| bitmaps.set_accepted_bitmap(gpa_start, gpa_end))
}

pub fn accept_guest_mem(
    gpa_start: GuestPhysAddr,
    gpa_end: GuestPhysAddr,
) -> Result<usize, TdxError> {
    if !gpa_start.is_page_aligned() || !gpa_end.is_page_aligned() {
        return Err(TdxError::UnalignedPhysAddr);
    }

    if let Some(ret) = set_accepted_bitmap(gpa_start, gpa_end) {
        ret
    } else {
        // Init GMEM_BITMAPS if it is not initialized yet. This
        // is required only once.
        init_gmem_bitmaps();
        set_accepted_bitmap(gpa_start, gpa_end).unwrap()
    }
}

fn modify_shared_bitmap(
    gpa_start: GuestPhysAddr,
    gpa_end: GuestPhysAddr,
    shared: bool,
) -> Option<Result<usize, TdxError>> {
    GMEM_BITMAPS.lock_read().as_ref().map(|bitmaps| {
        if shared {
            bitmaps.set_shared_bitmap(gpa_start, gpa_end)
        } else {
            bitmaps.clear_shared_bitmap(gpa_start, gpa_end)
        }
    })
}

#[allow(dead_code)]
pub fn convert_guest_mem(
    gpa_start: GuestPhysAddr,
    gpa_end: GuestPhysAddr,
    shared: bool,
) -> Result<usize, TdxError> {
    if !gpa_start.is_page_aligned() || !gpa_end.is_page_aligned() {
        return Err(TdxError::UnalignedPhysAddr);
    }

    if let Some(ret) = modify_shared_bitmap(gpa_start, gpa_end, shared) {
        ret
    } else {
        // Init GMEM_BITMAPS if it is not initialized yet. This
        // is required only once.
        init_gmem_bitmaps();
        modify_shared_bitmap(gpa_start, gpa_end, shared).unwrap()
    }
}

pub fn copy_from_gpa<T>(gpa: GuestPhysAddr) -> Result<T, TdxError>
where
    T: Sized + Copy,
{
    let size = size_of::<T>();
    let aligned_gpa_start = gpa.page_align();
    let aligned_gpa_end = (gpa + size).page_align_up();
    accept_guest_mem(aligned_gpa_start, aligned_gpa_end)?;
    GuestMemMap::<T>::new(gpa, size)
        .map_err(|e| {
            log::error!("copy_from_gpa failed to create GuestMemMap: {:?}", e);
            TdxError::ReadGuestMem
        })?
        .read()
        .map_err(|e| {
            log::error!("copy_from_gpa failed: {:?}", e);
            TdxError::ReadGuestMem
        })
}

pub fn copy_to_gpa<T>(gpa: GuestPhysAddr, buf: T) -> Result<(), TdxError>
where
    T: Sized + Copy,
{
    let size = size_of::<T>();
    let aligned_gpa_start = gpa.page_align();
    let aligned_gpa_end = (gpa + size).page_align_up();
    accept_guest_mem(aligned_gpa_start, aligned_gpa_end)?;
    GuestMemMap::<T>::new(gpa, size)
        .map_err(|e| {
            log::error!("copy_to_gpa failed to create GuestMemMap: {:?}", e);
            TdxError::WriteGuestMem
        })?
        .write(buf)
        .map_err(|e| {
            log::error!("copy_to_gpa failed: {:?}", e);
            TdxError::WriteGuestMem
        })
}

const ENTRY_COUNT: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PagingMode {
    Level2,
    Level3,
    Level4,
    Level5,
    UnSupported,
}

impl PagingMode {
    fn new(cr0: CR0Flags, cr4: CR4Flags, efer: EFERFlags) -> Self {
        if cr0.contains(CR0Flags::PG) {
            if cr4.contains(CR4Flags::PAE) {
                if cr4.contains(CR4Flags::LA57) {
                    PagingMode::Level5
                } else if efer.contains(EFERFlags::LMA) {
                    PagingMode::Level4
                } else {
                    PagingMode::Level3
                }
            } else {
                PagingMode::Level2
            }
        } else {
            PagingMode::UnSupported
        }
    }
}

impl From<PagingMode> for u64 {
    fn from(pm: PagingMode) -> Self {
        match pm {
            PagingMode::Level2 => 2,
            PagingMode::Level3 => 3,
            PagingMode::Level4 => 4,
            PagingMode::Level5 => 5,
            PagingMode::UnSupported => 0,
        }
    }
}

bitflags! {
    #[derive(Copy, Clone, Debug)]
    pub struct GuestMemAccessCode: u32 {
        const WRITE     = 1 << 0;
        const FETCH     = 1 << 1;
    }
}

struct GuestPageTableImmut {
    pm: PagingMode,
    level: u64,
    guard: PerCPUPageMappingGuard,
}

#[derive(Copy, Clone, Debug, Default)]
struct GuestPTEntry {
    val: GuestPhysAddr,
    level: u64,
}

impl GuestPTEntry {
    fn new(val: GuestPhysAddr, level: u64) -> Self {
        GuestPTEntry { val, level }
    }

    fn flags(&self) -> PTEntryFlags {
        PTEntryFlags::from_bits_truncate(self.val.bits() as u64)
    }

    fn is_present(&self) -> bool {
        self.flags().contains(PTEntryFlags::PRESENT)
    }

    fn is_huge(&self) -> bool {
        self.flags().contains(PTEntryFlags::HUGE)
    }

    fn is_writable(&self) -> bool {
        self.flags().contains(PTEntryFlags::WRITABLE)
    }

    fn is_nx(&self) -> bool {
        self.flags().contains(PTEntryFlags::NX)
    }

    fn is_user(&self) -> bool {
        self.flags().contains(PTEntryFlags::USER)
    }

    fn is_last(&self) -> bool {
        self.level == 1
    }

    fn is_leaf(&self) -> bool {
        self.is_present() && (self.is_huge() || self.is_last())
    }

    fn address(&self) -> GuestPhysAddr {
        GuestPhysAddr::from(self.val.bits() & 0x000f_ffff_ffff_f000)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PageWalkInfo {
    code: GuestMemAccessCode,
    is_user_mode_addr: bool,
    is_user_mode_access: bool,
    pse: bool,
    wp: bool,
    nxe: bool,
    is_smap_on: bool,
    is_smep_on: bool,
    acflag: bool,
}

#[derive(Debug)]
enum PageWalkError {
    NotPresent,
    NotWritable,
    NotFetchable,
    UserNotPermit,
    SuperRWNoAC,
    SuperNotWritable,
    SuperNotFetchable,
}

impl PageWalkInfo {
    fn new(
        cpl: u8,
        cr0: CR0Flags,
        cr4: CR4Flags,
        efer: EFERFlags,
        rflags: RFlags,
        pm: PagingMode,
        code: GuestMemAccessCode,
    ) -> Self {
        PageWalkInfo {
            code,
            is_user_mode_addr: true,
            is_user_mode_access: cpl == 3,
            pse: if pm == PagingMode::Level2 {
                cr4.contains(CR4Flags::PSE)
            } else {
                true
            },
            wp: cr0.contains(CR0Flags::WP),
            nxe: efer.contains(EFERFlags::NXE),
            is_smap_on: cr4.contains(CR4Flags::SMAP),
            is_smep_on: cr4.contains(CR4Flags::SMEP),
            acflag: rflags.contains(RFlags::AC),
        }
    }

    fn check_access(&mut self, entry: &GuestPTEntry) -> Result<GuestPhysAddr, PageWalkError> {
        if !entry.is_present() {
            // Entry is not present
            return Err(PageWalkError::NotPresent);
        }

        if !entry.is_user() {
            self.is_user_mode_addr = false;
        }

        if self.code.contains(GuestMemAccessCode::WRITE)
            && (self.is_user_mode_access || self.wp)
            && !entry.is_writable()
        {
            // User mode write with R/W = 0
            // Supervisor mode write with CR0.WP = 1 && R/W = 0
            return Err(PageWalkError::NotWritable);
        }

        if self.code.contains(GuestMemAccessCode::FETCH) && self.nxe && entry.is_nx() {
            // Fetch with IA32_EFER.NXE = 1 and XD = 1
            return Err(PageWalkError::NotFetchable);
        }

        if entry.is_leaf() {
            if self.is_user_mode_access && !self.is_user_mode_addr {
                // User mode access supervisor mode address
                return Err(PageWalkError::UserNotPermit);
            } else if !self.is_user_mode_access && self.is_user_mode_addr {
                // Supervisor mode access user mode address
                if self.is_smap_on && !self.acflag {
                    // Read/Write(CR0.WP = 0/1) with SMAP = 1 && rflags.ac = 0
                    return Err(PageWalkError::SuperRWNoAC);
                }

                if self.code.contains(GuestMemAccessCode::WRITE) && self.wp && !entry.is_writable()
                {
                    // Write with SMAP = 1 && rflags.ac = 1 && CR0.WP = 1 && R/W = 0
                    // Write with SMAP = 0 && CR0.WP = 1 && R/W = 0
                    return Err(PageWalkError::SuperNotWritable);
                }

                if self.code.contains(GuestMemAccessCode::FETCH)
                    && (self.is_smep_on || (self.nxe && entry.is_nx()))
                {
                    // Fetch with SMEP = 1 or IA32_EFER.NXE = 1 and XD = 1
                    return Err(PageWalkError::SuperNotFetchable);
                }
            }
        }

        Ok(entry.address())
    }
}

struct GuestPTPage {
    entries: [GuestPhysAddr; ENTRY_COUNT],
}

impl Index<usize> for GuestPTPage {
    type Output = GuestPhysAddr;

    fn index(&self, index: usize) -> &GuestPhysAddr {
        &self.entries[index]
    }
}

impl GuestPageTableImmut {
    fn new(gpa: GuestPhysAddr, pm: PagingMode, level: Option<u64>) -> Result<Self, TdxError> {
        if pm == PagingMode::UnSupported || !is_guest_phys_addr_valid(gpa) {
            return Err(TdxError::GuestPGT);
        }

        let level = if let Some(l) = level {
            if l > u64::from(pm) || l == 0 {
                return Err(TdxError::GuestPGT);
            }
            l
        } else {
            u64::from(pm)
        };

        let hpa = gpa.page_align().to_host_phys_addr();
        let guard = PerCPUPageMappingGuard::create(hpa, hpa + PAGE_SIZE, 0).map_err(|e| {
            log::error!("Failed to create PT guard for GuestPGT {:?}", e);
            TdxError::GuestPGT
        })?;

        Ok(GuestPageTableImmut { pm, level, guard })
    }

    fn index(&self, gva: GuestVirtAddr) -> usize {
        let bits = if self.pm <= PagingMode::Level3 {
            gva.bits() & 0xffffffff
        } else {
            gva.bits()
        };

        let width = if self.pm == PagingMode::Level2 { 10 } else { 9 };

        (bits >> (12 + width * (self.level - 1))) & ((1 << width) - 1)
    }

    fn next_level(&self) -> u64 {
        self.level - 1
    }

    fn phys_mask(&self) -> usize {
        let width = if self.pm == PagingMode::Level2 { 10 } else { 9 };

        (1 << (12 + width * (self.level - 1))) - 1
    }

    fn walk(
        &self,
        gva: GuestVirtAddr,
        pw_info: &mut PageWalkInfo,
    ) -> Result<Option<GuestPhysAddr>, TdxError> {
        let gpt_ptr = u64::from(self.guard.virt_addr()) as *const GuestPTPage;
        let gpt = unsafe { &*gpt_ptr.cast::<GuestPTPage>() };
        let entry = GuestPTEntry::new(gpt[self.index(gva)], self.level);

        match pw_info.check_access(&entry) {
            Ok(gpa) => {
                if (pw_info.pse && entry.is_huge()) || entry.is_last() {
                    Ok(Some(gpa + (gva.bits() & self.phys_mask())))
                } else {
                    let next_gpt = GuestPageTableImmut::new(gpa, self.pm, Some(self.next_level()))?;
                    next_gpt.walk(gva, pw_info)
                }
            }
            Err(e) => {
                log::error!(
                    "Failed to translate gva 0x{:x} at entry 0x{:x} level {}: {:?}",
                    gva,
                    entry.val,
                    entry.level,
                    e
                );
                Ok(None)
            }
        }
    }
}

pub fn gva2gpa(
    ctx: &GuestCpuContext,
    gva: GuestVirtAddr,
    code: GuestMemAccessCode,
) -> Result<Option<GuestPhysAddr>, TdxError> {
    let cr0 = CR0Flags::from_bits_truncate(ctx.get_cr0());
    let cr4 = CR4Flags::from_bits_truncate(ctx.get_cr4());
    let efer = EFERFlags::from_bits_truncate(ctx.get_efer());
    let rflags = RFlags::from_bits_truncate(ctx.get_rflags());
    let pm = PagingMode::new(cr0, cr4, efer);
    if pm == PagingMode::UnSupported {
        Ok(Some(GuestPhysAddr::new(gva.into())))
    } else {
        let guest_cr3 = GuestPhysAddr::from(ctx.get_cr3());
        let cpl = ctx.get_cpl();
        let mut pw_info = PageWalkInfo::new(cpl, cr0, cr4, efer, rflags, pm, code);
        let gpt = GuestPageTableImmut::new(guest_cr3, pm, None)?;

        gpt.walk(gva, &mut pw_info)
    }
}
