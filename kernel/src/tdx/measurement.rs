// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2024 Intel Corporation
//

extern crate alloc;

use crate::address::Address;
use crate::locking::SpinLock;
use crate::mm::{PerCPUPageMappingGuard, PAGE_SIZE};
use crate::tcg2::{
    TpmlDigestValues, TpmtHa, UefiPlatformFirmwareBlob2, EV_EFI_PLATFORM_FIRMWARE_BLOB2,
    EV_S_CRTM_VERSION, TPM2_HASH_ALG_ID_SHA1, TPM2_HASH_ALG_ID_SHA256, TPM2_HASH_ALG_ID_SHA384,
    TPM2_SHA1_SIZE, TPM2_SHA256_SIZE, TPM2_SHA384_SIZE,
};
use crate::utils::align_up;
use crate::vtpm::cmd::tpm2_pcr_extend::pcr_extend;
use crate::vtpm::cmd::tpm2_startup::startup;
use crate::vtpm::cmd::TPM_SU_CLEAR;
use alloc::string::String;
use alloc::vec;
use core::mem::size_of;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

use super::error::TdxError;
use super::tdvf::get_tdvf_sec_fv;

const PLATFORM_BLOB_DESC: &[u8] = b"TDVF";
const RTM_MEASUREMENT_STATE_SIZE: usize = 1024;
const HOB_TYPE_GUID_EXTENSION: u16 = 0x0004;
const HOB_TYPE_END_OF_HOB_LIST: u16 = 0xffff;
const GUIDED_HOB_HEADER_SIZE: usize = 24;
const TCG_EVENT2_ENTRY_HOB_GUID: [u8; 16] = [
    0x1e, 0x22, 0x6c, 0xd2, 0x30, 0x24, 0x8a, 0x4c, 0x91, 0x70, 0x3f, 0xcb, 0x45, 0x0, 0x41, 0x3f,
];

static VRTM_MEASUREMENT: SpinLock<RtmMeasurementState> = SpinLock::new(RtmMeasurementState::new());

fn hash_sha1(hash_data: &[u8], digest_sha1: &mut [u8; TPM2_SHA1_SIZE]) -> Result<(), TdxError> {
    let mut digest = Sha1::new();
    digest.update(hash_data);
    let hash = digest.finalize();

    if hash.len() != TPM2_SHA1_SIZE {
        Err(TdxError::Measurement)
    } else {
        digest_sha1.clone_from_slice(hash.as_slice());
        Ok(())
    }
}

fn hash_sha256(
    hash_data: &[u8],
    digest_sha256: &mut [u8; TPM2_SHA256_SIZE],
) -> Result<(), TdxError> {
    let mut digest = Sha256::new();
    digest.update(hash_data);
    let hash = digest.finalize();

    if hash.len() != TPM2_SHA256_SIZE {
        Err(TdxError::Measurement)
    } else {
        digest_sha256.clone_from_slice(hash.as_slice());
        Ok(())
    }
}

fn hash_sha384(
    hash_data: &[u8],
    digest_sha384: &mut [u8; TPM2_SHA384_SIZE],
) -> Result<(), TdxError> {
    let mut digest = Sha384::new();
    digest.update(hash_data);
    let hash = digest.finalize();

    if hash.len() != TPM2_SHA384_SIZE {
        Err(TdxError::Measurement)
    } else {
        digest_sha384.clone_from_slice(hash.as_slice());
        Ok(())
    }
}

fn create_digests(data: &[u8]) -> Result<TpmlDigestValues, TdxError> {
    let mut tpm2_digests = TpmlDigestValues::new();
    let mut digest_sha1 = [0u8; TPM2_SHA1_SIZE];
    let mut digest_sha256 = [0u8; TPM2_SHA256_SIZE];
    let mut digest_sha384 = [0u8; TPM2_SHA384_SIZE];

    hash_sha1(data, &mut digest_sha1)?;
    hash_sha256(data, &mut digest_sha256)?;
    hash_sha384(data, &mut digest_sha384)?;

    let sha1 = TpmtHa::new(TPM2_HASH_ALG_ID_SHA1, &digest_sha1[..]).ok_or(TdxError::Measurement)?;
    let sha256 =
        TpmtHa::new(TPM2_HASH_ALG_ID_SHA256, &digest_sha256).ok_or(TdxError::Measurement)?;
    let sha384 =
        TpmtHa::new(TPM2_HASH_ALG_ID_SHA384, &digest_sha384).ok_or(TdxError::Measurement)?;
    tpm2_digests
        .add_digest(&sha1)
        .map_err(|_| TdxError::Measurement)?;
    tpm2_digests
        .add_digest(&sha256)
        .map_err(|_| TdxError::Measurement)?;
    tpm2_digests
        .add_digest(&sha384)
        .map_err(|_| TdxError::Measurement)?;

    Ok(tpm2_digests)
}

struct RtmMeasurementState {
    size: usize,
    state: [u8; RTM_MEASUREMENT_STATE_SIZE],
}

impl RtmMeasurementState {
    const fn new() -> Self {
        RtmMeasurementState {
            size: 0,
            state: [0; RTM_MEASUREMENT_STATE_SIZE],
        }
    }

    fn size(&self) -> usize {
        self.size
    }

    fn state(&self) -> &[u8] {
        &self.state[..self.size]
    }

    fn build_guided_hob_header(&mut self, data_len: usize) -> Result<usize, TdxError> {
        // Length of HOB shall be 8 bytes aligned
        let aligned = align_up(data_len + GUIDED_HOB_HEADER_SIZE, 8);
        // Type of HOB
        self.write(&HOB_TYPE_GUID_EXTENSION.to_le_bytes())?;
        // Lenght of HOB
        self.write(&(aligned as u16).to_le_bytes())?;
        // Reserved field
        self.write(&0u32.to_le_bytes())?;
        // GUID
        self.write(&TCG_EVENT2_ENTRY_HOB_GUID)?;

        Ok(aligned)
    }

    fn write_event(
        &mut self,
        pcr_index: u32,
        event_type: u32,
        digests: &TpmlDigestValues,
        event_data: &[u8],
    ) -> Result<(), TdxError> {
        let digest_size = digests.size().ok_or(TdxError::Measurement)?;
        let event_len = size_of::<u32>() * 3 // PCR index, event type, digest count
            + digest_size
            + size_of::<u32>() // Event data size
            + event_data.len();
        let hob_len = self.build_guided_hob_header(event_len)?;
        self.write(&pcr_index.to_le_bytes())?;
        self.write(&event_type.to_le_bytes())?;
        self.write(&digests.count.to_le_bytes())?;
        digests
            .write_le_bytes(self.get_unused_mut(digest_size)?)
            .ok_or(TdxError::Measurement)?;
        self.write(&(event_data.len() as u32).to_le_bytes())?;
        self.write(event_data)?;
        // padding zeros
        let _ = self.get_unused_mut(hob_len - event_len - GUIDED_HOB_HEADER_SIZE)?;
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), TdxError> {
        // Type of HOB
        self.write(&HOB_TYPE_END_OF_HOB_LIST.to_le_bytes())?;
        // Lenght of HOB
        self.write(&8u32.to_le_bytes())?;
        // Reserved field
        self.write(&0u32.to_le_bytes())
    }

    fn write(&mut self, data: &[u8]) -> Result<(), TdxError> {
        let unused = self.get_unused_mut(data.len())?;
        unused[..data.len()].copy_from_slice(data);
        Ok(())
    }

    fn get_unused_mut(&mut self, require: usize) -> Result<&mut [u8], TdxError> {
        if require > RTM_MEASUREMENT_STATE_SIZE - self.size {
            return Err(TdxError::Measurement);
        }
        self.size += require;
        Ok(&mut self.state[self.size - require..self.size])
    }
}

pub fn extend_svsm_version() -> Result<(), TdxError> {
    let version = String::from(env!("CARGO_PKG_VERSION")) + "\0";
    let digests = create_digests(version.as_bytes())?;
    pcr_extend(0, &digests).map_err(|_| TdxError::Measurement)?;

    let mut vrtm = VRTM_MEASUREMENT.lock();
    vrtm.write_event(0, EV_S_CRTM_VERSION, &digests, version.as_bytes())
}

fn extend_tdvf_sec() -> Result<(), TdxError> {
    // Get the SEC Firmware Volume of TDVF
    let (base, len) = get_tdvf_sec_fv().map_err(|_| TdxError::Tdvf)?;

    // Map the code region of TDVF
    let guard =
        PerCPUPageMappingGuard::create(base, base.checked_add(len).ok_or(TdxError::Tdvf)?, 0)
            .map_err(|_| TdxError::Tdvf)?;
    let vstart = guard.virt_addr().as_ptr::<u8>();
    let mem: &[u8] = unsafe { core::slice::from_raw_parts(vstart, PAGE_SIZE) };

    let digests = create_digests(mem)?;
    pcr_extend(0, &digests).map_err(|_| TdxError::Measurement)?;

    // Put the firmware volume information into the event
    let fw_blob =
        UefiPlatformFirmwareBlob2::new(PLATFORM_BLOB_DESC, base.bits() as u64, len as u64)
            .ok_or(TdxError::Measurement)?;
    let fw_blob_size = fw_blob.size();
    let mut fw_blob_bytes = vec![0u8; fw_blob_size];
    fw_blob
        .write_bytes(&mut fw_blob_bytes)
        .ok_or(TdxError::Measurement)?;

    // Record the firmware blob event
    let mut vrtm = VRTM_MEASUREMENT.lock();
    vrtm.write_event(0, EV_EFI_PLATFORM_FIRMWARE_BLOB2, &digests, &fw_blob_bytes)
}

pub fn tdx_tpm_measurement_init() -> Result<(), TdxError> {
    // Send the start up command and initialize the TPM
    startup(TPM_SU_CLEAR).map_err(|_| TdxError::Measurement)?;

    // Then extend the SVSM version into PCR[0]
    extend_svsm_version()?;

    // Then extend the TDVF code FV into PCR[0]
    extend_tdvf_sec()?;

    // Finalize the virtual RTM events, append a end of hob list.
    let mut vrtm = VRTM_MEASUREMENT.lock();
    vrtm.finalize()
}
