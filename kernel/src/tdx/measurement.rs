// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2024 Intel Corporation
//

extern crate alloc;

use crate::address::Address;
use crate::mm::{PerCPUPageMappingGuard, PAGE_SIZE};
use crate::tcg2::{
    TpmlDigestValues, TpmtHa, TPM2_HASH_ALG_ID_SHA1, TPM2_HASH_ALG_ID_SHA256,
    TPM2_HASH_ALG_ID_SHA384, TPM2_SHA1_SIZE, TPM2_SHA256_SIZE, TPM2_SHA384_SIZE,
};
use crate::vtpm::cmd::tpm2_pcr_extend::pcr_extend;
use crate::vtpm::cmd::tpm2_startup::startup;
use crate::vtpm::cmd::TPM_SU_CLEAR;
use alloc::string::String;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

use super::error::TdxError;
use super::tdvf::get_tdvf_sec_fv;

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

pub fn extend_svsm_version() -> Result<(), TdxError> {
    let version = String::from(env!("CARGO_PKG_VERSION")) + "\0";
    let digests = create_digests(version.as_bytes())?;
    pcr_extend(0, &digests).map_err(|_| TdxError::Measurement)?;

    Ok(())
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
    pcr_extend(0, &digests).map_err(|_| TdxError::Measurement)
}

pub fn tdx_tpm_measurement_init() -> Result<(), TdxError> {
    // Send the start up command and initialize the TPM
    startup(TPM_SU_CLEAR).map_err(|_| TdxError::Measurement)?;

    // Then extend the SVSM version into PCR[0]
    extend_svsm_version()?;

    // Then extend the TDVF code FV into PCR[0]
    extend_tdvf_sec()
}
