// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

extern crate alloc;

use super::error::TdxError;
use super::tdcall::{td_accept_memory, tdvmcall_mapgpa};
use super::utils::td_convert_guest_pages;
use crate::address::{Address, GuestPhysAddr};
use crate::locking::RWLock;
use crate::mm::alloc::allocate_file_page_ref;
use crate::mm::guestmem::GuestMemMap;
use crate::mm::memory::get_memory_map;
use crate::mm::validate::{AtomicValidBitmap, ValidBitmap};
use crate::utils::{immut_after_init::ImmutAfterInitCell, MemoryRegion};
use alloc::vec::Vec;
use core::mem::size_of;

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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
