// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2024 Intel Corporation
//

extern crate alloc;

use alloc::vec::Vec;
use core::{
    mem::{align_of, size_of, size_of_val},
    str::FromStr,
};

use crate::{
    address::{Address, PhysAddr},
    error::SvsmError,
    fw_meta::{find_table, RawMetaBuffer, Uuid},
    mm::{PerCPUPageMappingGuard, PAGE_SIZE, SIZE_1G, SIZE_1M},
    utils::align_up,
};

const OVMF_TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
const OVMF_TABLE_TDX_METADATA_GUID: &str = "e47a6535-984a-4798-865e-4685a7bf8ec2";
const TDX_METADATA_GUID: &str = "e9eaf9f3-168e-44d5-a8eB-7f4d8738f6ae";

/// Section type for EFI Boot Firmware Volume.
pub(crate) const TDX_METADATA_SECTION_TYPE_BFV: u32 = 0;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TdxMetadataDescriptor {
    pub signature: u32,
    pub length: u32,
    pub version: u32,
    pub number_of_section_entry: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TdxMetadataSection {
    pub data_offset: u32,
    pub raw_data_size: u32,
    pub memory_address: u64,
    pub memory_data_size: u64,
    pub r#type: u32,
    pub attributes: u32,
}

#[repr(C)]
#[derive(Debug)]
struct FirmwareVolumeHeader {
    zero_vector: [u8; 16],
    file_system_guid: [u8; 16],
    fv_length: u64,
    signature: [u8; 4],
    attributes: u32,
    header_length: u16,
    checksum: u16,
    ext_header_offset: u16,
    reserved: u8,
    revision: u8,
}

fn find_firmware_volumes(
    image_base: PhysAddr,
    image_size: usize,
) -> Result<Vec<(PhysAddr, usize)>, SvsmError> {
    // Map the code region of TDVF
    let guard = PerCPUPageMappingGuard::create(
        image_base,
        image_base
            .checked_add(image_size)
            .ok_or(SvsmError::Firmware)?,
        0,
    )?;
    let vstart = guard.virt_addr().as_ptr::<u8>();
    let image: &[u8] = unsafe { core::slice::from_raw_parts(vstart, image_size) };

    let mut fvs = Vec::new();
    let mut offset = 0;
    while offset < image.len() {
        let header_start = offset;
        let header_end = header_start + size_of::<FirmwareVolumeHeader>();
        if header_end > image.len() {
            break;
        }
        let fv_hdr_ptr = image
            .get(header_start..header_end)
            .ok_or(SvsmError::Firmware)?
            .as_ptr()
            .cast::<FirmwareVolumeHeader>();

        // Safety: we have checked the pointer is within bounds.
        let fvh = unsafe { fv_hdr_ptr.read() };
        if fvh.signature == *b"_FVH" {
            // Firmware volume header found
            let volume_size = fvh.fv_length as usize;
            let end_pos = header_start + volume_size;
            if end_pos <= image.len() {
                let fv_base = image_base
                    .checked_add(header_start)
                    .ok_or(SvsmError::Firmware)?;
                fvs.push((fv_base, volume_size));
            }
            offset += volume_size
        } else {
            offset += 1;
        }
    }
    Ok(fvs)
}

// Returns the backward offset of metadata in the ROM space
fn get_metadata_offset() -> Result<u32, SvsmError> {
    // Map the metadata location which is defined by the firmware config
    let guard = PerCPUPageMappingGuard::create_4k(PhysAddr::from((4 * SIZE_1G) - PAGE_SIZE))?;
    let vstart = guard.virt_addr().as_ptr::<u8>();
    let table = unsafe { core::slice::from_raw_parts(vstart, PAGE_SIZE) };
    let raw_meta = unsafe { &*table.as_ptr().cast::<RawMetaBuffer>() };

    // Check the UUID
    let raw_uuid = raw_meta.header.uuid;
    let uuid = Uuid::from(&raw_uuid);
    let meta_uuid = Uuid::from_str(OVMF_TABLE_FOOTER_GUID)?;
    if uuid != meta_uuid {
        return Err(SvsmError::Firmware);
    }

    // Get the tables and their length
    let data_len = raw_meta.header.data_len().ok_or(SvsmError::Firmware)?;
    let data_start = size_of_val(&raw_meta.data)
        .checked_sub(data_len)
        .ok_or(SvsmError::Firmware)?;
    let raw_data = raw_meta.data.get(data_start..).ok_or(SvsmError::Firmware)?;

    // First check if this is the SVSM itself instead of OVMF
    let tdx_metadata_uuid = Uuid::from_str(OVMF_TABLE_TDX_METADATA_GUID)?;
    if let Some(data) = find_table(&tdx_metadata_uuid, raw_data) {
        if data.len() == size_of::<u32>() {
            // Safety: we just checked the length of data
            return Ok(u32::from_le_bytes(data.try_into().unwrap()));
        }
    }
    Err(SvsmError::Firmware)
}

// Validate the metadata and get the basic infomation from it if any
fn get_tdvf_bfv() -> Result<(PhysAddr, usize), SvsmError> {
    let offset = get_metadata_offset()?;
    let page = align_up(offset as usize + 16, PAGE_SIZE);
    if page > SIZE_1M * 2 {
        return Err(SvsmError::Firmware);
    }

    // Map the metadata location which is defined by the firmware config
    let guard = PerCPUPageMappingGuard::create_4k(PhysAddr::from((4 * SIZE_1G) - page))?;
    let vstart = guard.virt_addr().as_ptr::<u8>();
    let mem: &[u8] = unsafe { core::slice::from_raw_parts(vstart, PAGE_SIZE) };
    let metadata = &mem[page - offset as usize - 16..];

    // Then read the guid
    let metadata_guid = Uuid::from_str(TDX_METADATA_GUID)?;
    let actual_guid: [u8; 16] = metadata[..16].try_into().unwrap();
    if metadata_guid != Uuid::from(&actual_guid) {
        return Err(SvsmError::Firmware);
    }

    let tdx_meta_desc_ptr = metadata
        .get(16..16 + size_of::<TdxMetadataDescriptor>())
        .ok_or(SvsmError::Firmware)?
        .as_ptr()
        .cast::<TdxMetadataDescriptor>();

    // Check that the header pointer is aligned.
    if tdx_meta_desc_ptr.align_offset(align_of::<TdxMetadataDescriptor>()) != 0 {
        return Err(SvsmError::Firmware);
    }
    // Safety: we have checked the pointer is within bounds and aligned.
    let tdx_meta_desc = unsafe { tdx_meta_desc_ptr.read() };

    // Now find the descriptors
    let sections_start = 16 + size_of::<TdxMetadataDescriptor>();
    let num_section = tdx_meta_desc.number_of_section_entry as usize;
    let _ = num_section
        .checked_mul(size_of::<TdxMetadataSection>())
        .ok_or(SvsmError::Firmware)?;

    let tdx_sections_ptr = metadata
        .get(sections_start..sections_start + size_of::<TdxMetadataSection>())
        .ok_or(SvsmError::Firmware)?
        .as_ptr()
        .cast::<TdxMetadataSection>();

    for i in 0..num_section {
        let section = unsafe { tdx_sections_ptr.add(i).read() };
        let t = section.r#type;
        let mem_addr = section.memory_address as usize;
        let mem_size = section.memory_data_size as usize;
        let data_offset = section.data_offset as usize;
        let data_size = section.raw_data_size as usize;

        if (data_size == 0 && data_offset != 0)
            || (data_size != 0 && mem_size < data_size)
            || (mem_addr & 0xfff != 0)
        {
            return Err(SvsmError::Firmware);
        }
        match t {
            TDX_METADATA_SECTION_TYPE_BFV => return Ok((PhysAddr::new(mem_addr), mem_size)),
            _ => continue,
        }
    }

    Err(SvsmError::Firmware)
}

pub(crate) fn get_tdvf_firmware_volumes() -> Result<Vec<(PhysAddr, usize)>, SvsmError> {
    // Get the BFV base and size from TDX metadata.
    let (bfv_start, bfv_size) = get_tdvf_bfv()?;

    // Find the firmware volumes from the BFV of TDVF
    find_firmware_volumes(bfv_start, bfv_size)
}
