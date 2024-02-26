// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, GuestPhysAddr, VirtAddr};
use crate::cpu::features::cpu_type;
use crate::error::SvsmError;
use crate::mm::memory::is_guest_phys_addr_valid;
use crate::mm::pagetable::encrypt_mask;
use crate::mm::ptguards::PerCPUPageMappingGuard;
use crate::types::CpuType;
use core::arch::asm;
use core::marker::PhantomData;
use core::mem::{size_of, MaybeUninit};

#[allow(dead_code)]
#[inline]
pub fn read_u8(v: VirtAddr) -> Result<u8, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

    unsafe {
        asm!("1: movb ({0}), %al",
             "   xorq %rcx, %rcx",
             "2:",
             ".pushsection \"__exception_table\",\"a\"",
             ".balign 16",
             ".quad (1b)",
             ".quad (2b)",
             ".popsection",
                in(reg) v.bits(),
                out("rax") val,
                out("rcx") rcx,
                options(att_syntax, nostack));
    }

    let ret: u8 = (val & 0xff) as u8;
    if rcx == 0 {
        Ok(ret)
    } else {
        Err(SvsmError::InvalidAddress)
    }
}

#[allow(dead_code)]
#[inline]
pub fn write_u8(v: VirtAddr, val: u8) -> Result<(), SvsmError> {
    let mut rcx: u64;

    unsafe {
        asm!("1: movb %al, ({0})",
             "   xorq %rcx, %rcx",
             "2:",
             ".pushsection \"__exception_table\",\"a\"",
             ".balign 16",
             ".quad (1b)",
             ".quad (2b)",
             ".popsection",
                in(reg) v.bits(),
                in("rax") val as u64,
                out("rcx") rcx,
                options(att_syntax, nostack));
    }

    if rcx == 0 {
        Ok(())
    } else {
        Err(SvsmError::InvalidAddress)
    }
}

#[allow(dead_code)]
#[inline]
unsafe fn read_u16(v: VirtAddr) -> Result<u16, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

    asm!("1: movw ({0}), {1}",
         "   xorq %rcx, %rcx",
         "2:",
         ".pushsection \"__exception_table\",\"a\"",
         ".balign 16",
         ".quad (1b)",
         ".quad (2b)",
         ".popsection",
            in(reg) v.bits(),
            out(reg) val,
            out("rcx") rcx,
            options(att_syntax, nostack));

    let ret: u16 = (val & 0xffff) as u16;
    if rcx == 0 {
        Ok(ret)
    } else {
        Err(SvsmError::InvalidAddress)
    }
}

#[allow(dead_code)]
#[inline]
unsafe fn read_u32(v: VirtAddr) -> Result<u32, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

    asm!("1: movl ({0}), {1}",
         "   xorq %rcx, %rcx",
         "2:",
         ".pushsection \"__exception_table\",\"a\"",
         ".balign 16",
         ".quad (1b)",
         ".quad (2b)",
         ".popsection",
            in(reg) v.bits(),
            out(reg) val,
            out("rcx") rcx,
            options(att_syntax, nostack));

    let ret: u32 = (val & 0xffffffff) as u32;
    if rcx == 0 {
        Ok(ret)
    } else {
        Err(SvsmError::InvalidAddress)
    }
}

#[allow(dead_code)]
#[inline]
unsafe fn read_u64(v: VirtAddr) -> Result<u64, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

    asm!("1: movq ({0}), {1}",
         "   xorq %rcx, %rcx",
         "2:",
         ".pushsection \"__exception_table\",\"a\"",
         ".balign 16",
         ".quad (1b)",
         ".quad (2b)",
         ".popsection",
            in(reg) v.bits(),
            out(reg) val,
            out("rcx") rcx,
            options(att_syntax, nostack));

    if rcx == 0 {
        Ok(val)
    } else {
        Err(SvsmError::InvalidAddress)
    }
}

#[inline]
unsafe fn do_movsb<T>(src: *const T, dst: *mut T) -> Result<(), SvsmError> {
    let size: usize = size_of::<T>();
    let mut rcx: u64;

    asm!("1:cld
            rep movsb
          2:
         .pushsection \"__exception_table\",\"a\"
         .balign 16
         .quad (1b)
         .quad (2b)
         .popsection",
            inout("rsi") src => _,
            inout("rdi") dst => _,
            inout("rcx") size => rcx,
            options(att_syntax, nostack));

    if rcx == 0 {
        Ok(())
    } else {
        Err(SvsmError::InvalidAddress)
    }
}

#[derive(Debug)]
pub struct GuestPtr<T: Copy> {
    ptr: *mut T,
}

impl<T: Copy> GuestPtr<T> {
    #[inline]
    pub fn new(v: VirtAddr) -> Self {
        Self {
            ptr: v.as_mut_ptr::<T>(),
        }
    }

    #[inline]
    pub const fn from_ptr(p: *mut T) -> Self {
        Self { ptr: p }
    }

    #[inline]
    pub fn read(&self) -> Result<T, SvsmError> {
        let mut buf = MaybeUninit::<T>::uninit();

        unsafe {
            do_movsb(self.ptr, buf.as_mut_ptr())?;
            Ok(buf.assume_init())
        }
    }

    #[inline]
    pub fn write(&self, buf: T) -> Result<(), SvsmError> {
        unsafe { do_movsb(&buf, self.ptr) }
    }

    #[inline]
    pub fn write_ref(&self, buf: &T) -> Result<(), SvsmError> {
        unsafe { do_movsb(buf, self.ptr) }
    }

    #[inline]
    pub const fn cast<N: Copy>(&self) -> GuestPtr<N> {
        GuestPtr::from_ptr(self.ptr.cast())
    }

    #[inline]
    pub fn offset(&self, count: isize) -> Self {
        GuestPtr::from_ptr(self.ptr.wrapping_offset(count))
    }
}

#[derive(Debug)]
pub struct GuestMemMap<T> {
    guard: PerCPUPageMappingGuard,
    virt_off: usize,
    size: usize,
    _phantom: PhantomData<T>,
}

impl<T: Sized + Copy> GuestMemMap<T> {
    pub fn new(gpa: GuestPhysAddr, size: usize) -> Result<Self, SvsmError> {
        if !is_guest_phys_addr_valid(gpa) {
            return Err(SvsmError::GuestMemMap);
        }

        let hpa = gpa.page_align().to_host_phys_addr();
        let hpa_end = (gpa + size).page_align_up().to_host_phys_addr();
        let guard = PerCPUPageMappingGuard::create(hpa, hpa_end, 0).map_err(|e| {
            log::error!("Failed to create GuestMem {:?}", e);
            SvsmError::GuestMemMap
        })?;

        Ok(GuestMemMap {
            guard,
            virt_off: gpa - gpa.page_align(),
            size: hpa_end - hpa,
            _phantom: PhantomData,
        })
    }

    pub fn virt_addr(&self) -> VirtAddr {
        self.guard.virt_addr() + self.virt_off
    }

    pub fn read(&self) -> Result<T, SvsmError> {
        let ptr = GuestPtr::<T>::new(self.virt_addr());

        // Read size is larger than mapped size
        if size_of::<T>() > self.size {
            Err(SvsmError::GuestMemMapSize)
        } else {
            ptr.read().map_err(|e| {
                log::error!("Failed to read GuestPtr: {:?}", e);
                SvsmError::GuestMemMapRead
            })
        }
    }

    pub fn write(&self, buf: T) -> Result<(), SvsmError> {
        let ptr = GuestPtr::<T>::new(self.virt_addr());

        // Write size is larger than mapped size
        if size_of::<T>() > self.size {
            Err(SvsmError::GuestMemMapSize)
        } else {
            ptr.write(buf).map_err(|e| {
                log::error!("Failed to write GuestPtr: {:?}", e);
                SvsmError::GuestMemMapWrite
            })
        }
    }
}

pub fn gpa_is_shared(gpa: GuestPhysAddr) -> bool {
    // GuestPhysAddr and PhysAddr are using the same bit as encryption-bit mask
    match cpu_type() {
        CpuType::Sev => (gpa.bits() & encrypt_mask()) == 0,
        CpuType::Td => (gpa.bits() & encrypt_mask()) != 0,
    }
}

pub fn gpa_strip_c_bit(gpa: GuestPhysAddr) -> GuestPhysAddr {
    GuestPhysAddr::from(gpa.bits() & !encrypt_mask())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "inline assembly")]
    fn test_read_u8_valid_address() {
        // Create a region to read from
        let test_buffer: [u8; 6] = [0; 6];
        let test_address = VirtAddr::from(test_buffer.as_ptr());

        let result = read_u8(test_address).unwrap();

        assert_eq!(result, test_buffer[0]);
    }

    #[test]
    #[cfg_attr(miri, ignore = "inline assembly")]
    fn test_write_u8_valid_address() {
        // Create a mutable region we can write into
        let mut test_buffer: [u8; 6] = [0; 6];
        let test_address = VirtAddr::from(test_buffer.as_mut_ptr());
        let data_to_write = 0x42;

        write_u8(test_address, data_to_write).unwrap();

        assert_eq!(test_buffer[0], data_to_write);
    }
}
