// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//

use crate::error::SvsmError;
use core::mem::size_of;

pub const EV_NO_ACTION: u32 = 0x0000_0003;
pub const EV_SEPARATOR: u32 = 0x0000_0004;
pub const EV_S_CRTM_VERSION: u32 = 0x00000008;
pub const EV_PLATFORM_CONFIG_FLAGS: u32 = 0x0000_000A;
pub const EV_EFI_EVENT_BASE: u32 = 0x8000_0000;
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB2: u32 = EV_EFI_EVENT_BASE + 0xA;
pub const EV_EFI_HANDOFF_TABLES2: u32 = EV_EFI_EVENT_BASE + 0xB;

pub const TPM2_HASH_ALG_ID_SHA1: u16 = 0x4;
pub const TPM2_HASH_ALG_ID_SHA256: u16 = 0xb;
pub const TPM2_HASH_ALG_ID_SHA384: u16 = 0xc;
pub const TPM2_HASH_ALG_ID_SHA512: u16 = 0xd;

pub const TPM2_SHA1_SIZE: usize = 20;
pub const TPM2_SHA256_SIZE: usize = 32;
pub const TPM2_SHA384_SIZE: usize = 48;
pub const TPM2_SHA512_SIZE: usize = 64;

const MAX_TPM2_HASH_SIZE: usize = TPM2_SHA512_SIZE;
const DIGEST_COUNT: usize = 5;
const MAX_PLATFORM_BLOB_DESC_SIZE: usize = 255;

#[repr(C)]
#[derive(Debug, Default)]
pub struct Tcg2EventHeader {
    pub mr_index: u32,
    pub event_type: u32,
    pub digest: TpmlDigestValues,
    pub event_size: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct TcgPcrEventHeader {
    pub mr_index: u32,
    pub event_type: u32,
    pub digest: [u8; 20],
    pub event_size: u32,
}

/// TCG_EfiSpecIdEvent is the first event in the event log
/// It is used to determine the version and format of the events in the log, identify
/// the number and size of the recorded digests
///
/// Defined in TCG PC Client Platform Firmware Profile Specification:
/// 'Table 20 TCG_EfiSpecIdEvent'
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct TcgEfiSpecIdevent {
    pub signature: [u8; 16],
    pub platform_class: u32,
    pub spec_version_minor: u8,
    pub spec_version_major: u8,
    pub spec_errata: u8,
    pub uintn_size: u8,
    // This field is added in "Spec ID Event03".
    // pub number_of_algorithms: u32,
    // This field is added in "Spec ID Event03".
    // pub digest_sizes: [TcgEfiSpecIdEventAlgorithmSize; number_of_algorithms],
    // This field is added in "Spec ID Event03".
    // pub vendor_info_size: u8,
    // This field is added in "Spec ID Event03".
    // pub vendor_info: [u8; vendor_info_size],
}

impl TcgEfiSpecIdevent {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct TcgEfiSpecIdEventAlgorithmSize {
    algorithm_id: u16,
    digest_size: u16,
}

/// Used to record the firmware blob information into event log.
///
/// Defined in TCG PC Client Platform Firmware Profile Specification section
/// 'UEFI_PLATFORM_FIRMWARE_BLOB Structure Definition'
#[derive(Debug)]
pub struct UefiPlatformFirmwareBlob2 {
    pub blob_desc_size: u8,
    pub blob_desc: [u8; MAX_PLATFORM_BLOB_DESC_SIZE],
    pub base: u64,
    pub length: u64,
}

impl UefiPlatformFirmwareBlob2 {
    pub fn new(desc: &[u8], base: u64, length: u64) -> Option<Self> {
        if desc.len() > MAX_PLATFORM_BLOB_DESC_SIZE {
            return None;
        }

        let mut fw_blob = UefiPlatformFirmwareBlob2 {
            blob_desc_size: 0,
            blob_desc: [0; MAX_PLATFORM_BLOB_DESC_SIZE],
            base,
            length,
        };
        fw_blob.blob_desc[..desc.len()].copy_from_slice(desc);
        fw_blob.blob_desc_size = desc.len() as u8;

        Some(fw_blob)
    }

    pub fn write_bytes(&self, bytes: &mut [u8]) -> Option<usize> {
        let desc_size = self.blob_desc_size as usize;
        let mut idx = 0;

        // Write blob descriptor size
        bytes[idx] = self.blob_desc_size;
        idx = idx.checked_add(1)?;

        // Write blob descriptor
        bytes[idx..idx + desc_size].copy_from_slice(&self.blob_desc[..desc_size]);
        idx = idx.checked_add(desc_size)?;

        // Write blob base address
        bytes[idx..idx + size_of::<u64>()].copy_from_slice(&self.base.to_le_bytes());
        idx = idx.checked_add(size_of::<u64>())?;

        // Write blob length
        bytes[idx..idx + size_of::<u64>()].copy_from_slice(&self.length.to_le_bytes());
        idx = idx.checked_add(size_of::<u64>())?;

        Some(idx)
    }

    pub fn size(&self) -> usize {
        self.blob_desc_size as usize + size_of::<u64>() * 2 + size_of::<u8>()
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct TpmlDigestValues {
    pub count: u32,
    // Support all the hash algorithms
    pub digests: [TpmtHa; DIGEST_COUNT],
}

impl TpmlDigestValues {
    pub fn new() -> TpmlDigestValues {
        Self {
            count: 0,
            digests: [TpmtHa::default(); DIGEST_COUNT],
        }
    }

    pub fn size(&self) -> Option<usize> {
        let mut size = 0;
        for digest in &self.digests[..self.count as usize] {
            size += digest.size()?;
        }
        Some(size)
    }

    pub fn add_digest(&mut self, digest: &TpmtHa) -> Result<(), SvsmError> {
        let count = self.count as usize;
        let hash_size = get_hash_size(digest.hash_alg);
        if hash_size.is_none() || count == DIGEST_COUNT {
            return Err(SvsmError::Tcg2);
        }

        self.digests[count] = *digest;
        self.count += 1;

        Ok(())
    }

    pub fn write_le_bytes(&self, out: &mut [u8]) -> Option<usize> {
        self.write_bytes(false, out)
    }

    pub fn write_be_bytes(&self, out: &mut [u8]) -> Option<usize> {
        self.write_bytes(true, out)
    }

    fn write_bytes(&self, big_endian: bool, out: &mut [u8]) -> Option<usize> {
        let mut offset = 0;
        if out.len() < self.size()? {
            return None;
        }

        for digest in &self.digests[..self.count as usize] {
            let digest_size = digest.size()?;
            if digest_size > out.len() - offset {
                return None;
            }
            if big_endian {
                digest.write_be_bytes(&mut out[offset..offset + digest_size])?
            } else {
                digest.write_le_bytes(&mut out[offset..offset + digest_size])?
            };
            offset += digest_size;
        }

        Some(offset)
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct TpmtHa {
    pub hash_alg: u16,
    pub digest: TpmuHa,
}

impl TpmtHa {
    pub fn new(hash_alg: u16, hash: &[u8]) -> Option<TpmtHa> {
        let hash_size = get_hash_size(hash_alg)?;
        if hash.len() != hash_size {
            return None;
        }

        let mut digest = TpmtHa {
            hash_alg,
            ..Default::default()
        };
        digest.digest.hash[..hash_size].copy_from_slice(hash);

        Some(digest)
    }

    pub fn size(&self) -> Option<usize> {
        self.hash_size().map(|size| size + 2)
    }

    pub fn hash_size(&self) -> Option<usize> {
        get_hash_size(self.hash_alg)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<TpmtHa> {
        let hash_alg = u16::from_be_bytes([bytes[0], bytes[1]]);
        let hash_size = get_hash_size(hash_alg)?;
        if bytes.len() < hash_size + 2 {
            return None;
        }

        TpmtHa::new(hash_alg, &bytes[2..hash_size + 2])
    }

    pub fn write_le_bytes(&self, out: &mut [u8]) -> Option<usize> {
        self.write_bytes(false, out)
    }

    pub fn write_be_bytes(&self, out: &mut [u8]) -> Option<usize> {
        self.write_bytes(true, out)
    }

    fn write_bytes(&self, big_endian: bool, out: &mut [u8]) -> Option<usize> {
        let hash_size = self.hash_size()?;
        let size = hash_size + 2;
        if out.len() < size {
            return None;
        }

        if big_endian {
            out[..2].copy_from_slice(&self.hash_alg.to_be_bytes());
        } else {
            out[..2].copy_from_slice(&self.hash_alg.to_le_bytes());
        }
        out[2..2 + hash_size].copy_from_slice(&self.digest.hash[..hash_size]);

        Some(size)
    }
}

fn get_hash_size(alg_id: u16) -> Option<usize> {
    match alg_id {
        TPM2_HASH_ALG_ID_SHA1 => Some(TPM2_SHA1_SIZE),
        TPM2_HASH_ALG_ID_SHA256 => Some(TPM2_SHA256_SIZE),
        TPM2_HASH_ALG_ID_SHA384 => Some(TPM2_SHA384_SIZE),
        TPM2_HASH_ALG_ID_SHA512 => Some(TPM2_SHA512_SIZE),
        _ => None,
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TpmuHa {
    pub hash: [u8; MAX_TPM2_HASH_SIZE],
}

impl Default for TpmuHa {
    fn default() -> Self {
        TpmuHa {
            hash: [0; MAX_TPM2_HASH_SIZE],
        }
    }
}
