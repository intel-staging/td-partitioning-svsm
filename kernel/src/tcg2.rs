// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//

use crate::error::SvsmError;
use bitflags::bitflags;
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
const VENDER_INFO: &[u8] = b"COCONUTSVSM";

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct HashAlgorithms: u32 {
        const SHA1 = 0b00000001;
        const SHA256 = 0b00000010;
        const SHA384 = 0b00000100;
        const SHA512 = 0b00001000;
    }
}

impl HashAlgorithms {
    pub fn algorithm_num(&self) -> u32 {
        let v = self.bits() & 0x0000_ffff;
        u32::count_ones(v)
    }
}

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

impl TcgPcrEventHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, size_of::<Self>()) }
    }
}

/// TCG_EfiSpecIdEvent is the first event in the event log
/// It is used to determine the version and format of the events in the log, identify
/// the number and size of the recorded digests
///
/// Defined in TCG PC Client Platform Firmware Profile Specification:
/// 'Table 20 TCG_EfiSpecIdEvent'
#[repr(C)]
#[derive(Debug, Clone, Copy)]
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

impl Default for TcgEfiSpecIdevent {
    fn default() -> Self {
        Self {
            signature: *b"Spec ID Event03\0",
            platform_class: 0,
            spec_version_minor: 0,
            spec_version_major: 0x2,
            spec_errata: 105,
            uintn_size: 0x2,
        }
    }
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

#[derive(Debug)]
pub struct Tcg2EventLog<'a> {
    log: &'a mut [u8],
    offset: usize,
    hash_algorithms: HashAlgorithms,
}

impl<'a> Tcg2EventLog<'a> {
    pub fn new(
        mem: &'a mut [u8],
        hash_algorithms: HashAlgorithms,
    ) -> Result<Tcg2EventLog<'a>, SvsmError> {
        let mut event_log = Tcg2EventLog {
            log: mem,
            offset: 0,
            hash_algorithms,
        };

        // Create the TCG_EfiSpecIDEvent as the first event
        event_log.log_spec_id_event()?;

        Ok(event_log)
    }

    pub fn create_tcg2_event(
        &mut self,
        mr_index: u32,
        event_type: u32,
        event_data: &[&[u8]],
        hash_data: &[u8],
    ) -> Result<TpmlDigestValues, SvsmError> {
        let digests = calculate_digests(self.hash_algorithms, hash_data)?;
        self.log_tcg2_event(mr_index, event_type, event_data, &digests)?;

        Ok(digests)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.log[..self.offset]
    }

    fn log_spec_id_event(&mut self) -> Result<usize, SvsmError> {
        let first = TcgEfiSpecIdevent::default();
        let mut event_data_size = size_of::<TcgEfiSpecIdevent>() + size_of::<u32>(); // header + number_of_algorithms
        let number_of_algorithms = self.hash_algorithms.algorithm_num();
        event_data_size += size_of::<TcgEfiSpecIdEventAlgorithmSize>() * number_of_algorithms as usize
            + size_of::<u8>()  // vendor_info_size
            + VENDER_INFO.len(); // vendor_info

        let event_size = size_of::<TcgPcrEventHeader>()
            .checked_add(event_data_size)
            .ok_or(SvsmError::Tcg2)?;

        if self.offset.checked_add(event_size).ok_or(SvsmError::Tcg2)? > self.log.len() {
            return Err(SvsmError::Tcg2);
        }

        let pcr_header = TcgPcrEventHeader {
            mr_index: 0,
            event_type: EV_NO_ACTION,
            digest: [0u8; 20],
            event_size: event_data_size as u32,
        };

        self.write(pcr_header.as_bytes());

        // Write `TcgEfiSpecIdevent``
        self.write(first.as_bytes());
        self.write(&number_of_algorithms.to_le_bytes());
        if self.hash_algorithms.contains(HashAlgorithms::SHA1) {
            self.write(&TPM2_HASH_ALG_ID_SHA1.to_le_bytes());
            self.write(&(TPM2_SHA1_SIZE as u16).to_le_bytes());
        }
        if self.hash_algorithms.contains(HashAlgorithms::SHA256) {
            self.write(&TPM2_HASH_ALG_ID_SHA256.to_le_bytes());
            self.write(&(TPM2_SHA256_SIZE as u16).to_le_bytes());
        }
        if self.hash_algorithms.contains(HashAlgorithms::SHA384) {
            self.write(&TPM2_HASH_ALG_ID_SHA384.to_le_bytes());
            self.write(&(TPM2_SHA384_SIZE as u16).to_le_bytes());
        }
        self.write(&[VENDER_INFO.len() as u8]);
        self.write(VENDER_INFO);

        Ok(self.offset)
    }

    fn log_tcg2_event(
        &mut self,
        mr_index: u32,
        event_type: u32,
        event_data: &[&[u8]],
        digests: &TpmlDigestValues,
    ) -> Result<(), SvsmError> {
        let event_data_size: usize = event_data.iter().map(|&data| data.len()).sum();
        let digest_size = digests.size().ok_or(SvsmError::Tcg2)?;
        let event_size = size_of::<u32>() * 3
            + digest_size
                .checked_add(event_data_size)
                .ok_or(SvsmError::Tcg2)?;

        if self.offset.checked_add(event_size).ok_or(SvsmError::Tcg2)? > self.log.len() {
            return Err(SvsmError::Tcg2);
        }

        // Write the event header into event log memory and update the 'size'
        self.write(&mr_index.to_le_bytes());
        self.write(&event_type.to_le_bytes());
        let size = digests
            .write_le_bytes(&mut self.log[self.offset..])
            .ok_or(SvsmError::Tcg2)?;
        self.offset += size;
        self.write(&event_size.to_le_bytes());

        // Fill the event data into event log
        for &data in event_data {
            self.write(data);
        }

        Ok(())
    }

    fn write(&mut self, data: &[u8]) {
        let idx = self.offset;
        self.log[idx..idx + data.len()].copy_from_slice(data);
        self.offset += data.len();
    }
}

fn calculate_digests(
    hash_algs: HashAlgorithms,
    data: &[u8],
) -> Result<TpmlDigestValues, SvsmError> {
    let mut digests = TpmlDigestValues::new();

    if hash_algs.contains(HashAlgorithms::SHA1) {
        let digest = hash_sha1(data);
        digests.add_digest(&digest)?;
    }

    if hash_algs.contains(HashAlgorithms::SHA256) {
        let digest = hash_sha256(data);
        digests.add_digest(&digest)?;
    }

    if hash_algs.contains(HashAlgorithms::SHA1) {
        let digest = hash_sha384(data);
        digests.add_digest(&digest)?;
    }

    Ok(digests)
}

fn hash_sha1(data: &[u8]) -> TpmtHa {
    use sha1::{Digest, Sha1};

    let mut digest = Sha1::new();
    digest.update(data);
    let hash = digest.finalize();
    assert_eq!(hash.as_slice().len(), TPM2_SHA1_SIZE);

    let mut digest = TpmtHa {
        hash_alg: TPM2_HASH_ALG_ID_SHA1,
        digest: Default::default(),
    };
    digest.digest.hash[..hash.len()].clone_from_slice(hash.as_slice());
    digest
}

fn hash_sha256(data: &[u8]) -> TpmtHa {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(data);
    let hash = digest.finalize();
    assert_eq!(hash.as_slice().len(), TPM2_SHA256_SIZE);

    let mut digest = TpmtHa {
        hash_alg: TPM2_HASH_ALG_ID_SHA256,
        digest: Default::default(),
    };
    digest.digest.hash[..hash.len()].clone_from_slice(hash.as_slice());
    digest
}

fn hash_sha384(data: &[u8]) -> TpmtHa {
    use sha2::{Digest, Sha384};

    let mut digest = Sha384::new();
    digest.update(data);
    let hash = digest.finalize();
    assert_eq!(hash.as_slice().len(), TPM2_SHA384_SIZE);

    let mut digest = TpmtHa {
        hash_alg: TPM2_HASH_ALG_ID_SHA384,
        digest: Default::default(),
    };
    digest.digest.hash[..hash.len()].clone_from_slice(hash.as_slice());
    digest
}
