// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//
// Author: Peter Fang <peter.fang@intel.com>

extern crate alloc;

use super::error::TdxError;
use super::utils::TdpVmId;
use crate::mm::alloc::allocate_page;
use crate::mm::PAGE_SIZE;
use crate::tdx::utils::td_set_msr_bitmap;
use alloc::collections::btree_map::BTreeMap;
use core::mem::size_of;

const MSR_BITMAP_WRITE_OFFSET: u32 = 2048 / size_of::<u64>() as u32;
const MSR_BITMAP_HI_MSR_OFFSET: u32 = 1024 / size_of::<u64>() as u32;

#[derive(Debug)]
pub struct MsrBitmap {
    page: &'static mut [u64; PAGE_SIZE / size_of::<u64>()],
}

impl MsrBitmap {
    pub fn new() -> Self {
        let page = allocate_page().expect("Failed to allocate MSR bitmap page");
        unsafe {
            // The default value of the MSR exit bitmaps shadow page is all-1
            page.as_mut_ptr::<u8>().write_bytes(0xff, PAGE_SIZE);

            MsrBitmap {
                page: page
                    .as_mut_ptr::<[u64; PAGE_SIZE / size_of::<u64>()]>()
                    .as_mut()
                    .unwrap(),
            }
        }
    }
}

#[allow(dead_code)]
pub enum InterceptMsrType {
    Disable,
    Read,
    Write,
    ReadWrite,
}

pub struct MsrBitmapRef<'a> {
    vm_id: TdpVmId,
    bitmap: &'a mut MsrBitmap,
    dirty: BTreeMap<u32, u64>,
}

impl<'a> MsrBitmapRef<'a> {
    pub fn new(vm_id: TdpVmId, bitmap: &'a mut MsrBitmap) -> Self {
        MsrBitmapRef {
            vm_id,
            bitmap,
            dirty: BTreeMap::new(),
        }
    }

    fn msr_write_offset(read_offset: u32) -> u32 {
        read_offset + MSR_BITMAP_WRITE_OFFSET
    }

    // Returns (read_offset, write_offset)
    fn msr_offset(msr: u32) -> Option<(u32, u32)> {
        let off = (msr & 0x1fffu32) / u64::BITS;
        match msr {
            0..=0x1fff => {
                let read_off = off;
                Some((read_off, Self::msr_write_offset(read_off)))
            }
            0xc0000000..=0xc0001fff => {
                let read_off = off + MSR_BITMAP_HI_MSR_OFFSET;
                Some((read_off, Self::msr_write_offset(read_off)))
            }
            _ => None,
        }
    }

    fn msr_bit(msr: u32) -> u64 {
        1u64 << (msr & (u64::BITS - 1))
    }

    fn update_dirty(&mut self, offset: u32, bit: u64) {
        if let Some(m) = self.dirty.get_mut(&offset) {
            *m |= bit;
        } else {
            let _ = self.dirty.insert(offset, bit);
        }
    }

    pub fn intercept(&mut self, msr: u32, inttype: InterceptMsrType) -> Result<(), TdxError> {
        let (read_off, write_off) = match Self::msr_offset(msr) {
            Some((r, w)) => (r, w),
            _ => return Err(TdxError::Vmsr),
        };

        let bit = Self::msr_bit(msr);

        match inttype {
            InterceptMsrType::Read | InterceptMsrType::ReadWrite => {
                if self.bitmap.page[read_off as usize] & bit == 0 {
                    self.bitmap.page[read_off as usize] |= bit;
                    self.update_dirty(read_off, bit);
                }
            }
            _ => {
                if self.bitmap.page[read_off as usize] & bit != 0 {
                    self.bitmap.page[read_off as usize] &= !bit;
                    self.update_dirty(read_off, bit);
                }
            }
        }

        match inttype {
            InterceptMsrType::Write | InterceptMsrType::ReadWrite => {
                if self.bitmap.page[write_off as usize] & bit == 0 {
                    self.bitmap.page[write_off as usize] |= bit;
                    self.update_dirty(write_off, bit);
                }
            }
            _ => {
                if self.bitmap.page[write_off as usize] & bit != 0 {
                    self.bitmap.page[write_off as usize] &= !bit;
                    self.update_dirty(write_off, bit);
                }
            }
        }

        Ok(())
    }

    pub fn is_dirty(&self) -> bool {
        !self.dirty.is_empty()
    }
}

impl Drop for MsrBitmapRef<'_> {
    fn drop(&mut self) {
        for (&offset, &mask) in self.dirty.iter() {
            td_set_msr_bitmap(self.vm_id, offset, self.bitmap.page[offset as usize], mask).unwrap();
        }
    }
}
