// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Jiaqi Gao <jiaqi.gao@intel.com>

extern crate alloc;

use alloc::vec::Vec;
use core::cell::OnceCell;

use super::{
    cmd::{
        tpm2_create_primary::create_primary,
        tpm2_nv_define_space::nv_define_space,
        tpm2_nv_write::{nv_write, MAX_NV_INDEX_SIZE},
        *,
    },
    VtpmError,
};
use crate::{error::SvsmError, locking::SpinLock};
use tpm2_evict_control::evict_control;

const TPM2_EK_ECC_SECP384R1_HANDLE: u32 = 0x81010016;
// For ECC follow "TCG EK Credential Profile For TPM Family 2.0; Level 0"
// Specification Version 2.3; Revision 2; 23 July 2020
// Section 2.2.1.5.1
const TPM2_NV_INDEX_ECC_SECP384R1_HI_EKCERT: u32 = 0x01c00016;
// Section 2.2.1.5.2
const TPM2_NV_INDEX_VTPM_CA_CERT_CHAIN: u32 = 0x01c00100;
const TPMU_SYM_KEY_BITS: u16 = 256;

pub(crate) static TPM_EK: SpinLock<OnceCell<EndorsementKey>> = SpinLock::new(OnceCell::new());

#[derive(Debug)]
pub struct EndorsementKey {
    pub handle: u32,
    pub public_key: Vec<u8>,
}

impl EndorsementKey {
    fn new(handle: u32, point_x: &[u8], point_y: &[u8]) -> Self {
        let mut public_key = Vec::new();
        // TPM supports uncompressed form only
        public_key.push(0x04);
        public_key.extend_from_slice(point_x);
        public_key.extend_from_slice(point_y);

        Self { handle, public_key }
    }
}

pub fn create_tpm_ek() -> Result<Vec<u8>, SvsmError> {
    // Set the handle to the global data
    Ok(TPM_EK
        .lock()
        .get_or_init(|| create_tpm_ek_ec384().expect("Failed to create EK"))
        .public_key
        .clone())
}

fn create_tpm_ek_ec384() -> Result<EndorsementKey, VtpmError> {
    let mut public_area = Vec::new();
    public_area.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    public_area.extend_from_slice(&TPM_ALG_SHA384.to_be_bytes());

    // Object attributes
    let object_attributes = TPMA_OBJ_FIXED_TPM
        | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_SENSITIVEDATAORIGIN
        | TPMA_OBJECT_USERWITHAUTH
        | TPMA_OBJECT_ADMINWITHPOLICY
        | TPMA_OBJECT_RESTRICTED
        | TPMA_OBJECT_DECRYPT;
    public_area.extend_from_slice(&object_attributes.to_be_bytes());

    // Policy digest for authentication
    let policy_digest: [u8; 48] = [
        0xb2, 0x6e, 0x7d, 0x28, 0xd1, 0x1a, 0x50, 0xbc, 0x53, 0xd8, 0x82, 0xbc, 0xf5, 0xfd, 0x3a,
        0x1a, 0x07, 0x41, 0x48, 0xbb, 0x35, 0xd3, 0xb4, 0xe4, 0xcb, 0x1c, 0x0a, 0xd9, 0xbd, 0xe4,
        0x19, 0xca, 0xcb, 0x47, 0xba, 0x09, 0x69, 0x96, 0x46, 0x15, 0x0f, 0x9f, 0xc0, 0x00, 0xf3,
        0xf8, 0x0e, 0x12,
    ];
    public_area.extend_from_slice(&(policy_digest.len() as u16).to_be_bytes());
    public_area.extend_from_slice(&policy_digest);

    // EC parameters for TPM_ECC_NIST_P384
    // symmetric: TPM_ALG_AES, 256bit, TPM_ALG_CFB
    let symmetric: &[u8] = &[
        TPM2_ALG_AES.to_be_bytes(),
        TPMU_SYM_KEY_BITS.to_be_bytes(),
        TPM2_ALG_CFB.to_be_bytes(),
    ]
    .concat();
    public_area.extend_from_slice(symmetric);
    public_area.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes());

    // TPM_ECC_NIST_P384
    public_area.extend_from_slice(&TPM_ECC_NIST_P384.to_be_bytes());
    public_area.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes());
    public_area.extend_from_slice(&0u32.to_be_bytes());

    // Run the TPM command `Tpm2_CreatePrimary`
    let primary_response =
        create_primary(TPM2_RH_ENDORSEMENT, &public_area).map_err(VtpmError::RunCommand)?;

    // Parse the public key from response
    let (x, y) = parse_public_area(&primary_response.public_area)?;

    // Make EK persistent
    evict_control(primary_response.handle, TPM2_EK_ECC_SECP384R1_HANDLE).unwrap();

    Ok(EndorsementKey::new(primary_response.handle, &x, &y))
}

pub(crate) fn parse_public_area(public_area: &[u8]) -> Result<(Vec<u8>, Vec<u8>), VtpmError> {
    if public_area.len() < 4 {
        return Err(VtpmError::RunCommand(TpmCommandError::UnexpectedResponse));
    }

    // Parse the type, offset 0
    let type_offset = 0;
    let type_field = u16::from_be_bytes(
        public_area[type_offset..type_offset + 2]
            .try_into()
            .unwrap(),
    );

    if type_field != TPM_ALG_ECC {
        return Err(VtpmError::EndorsementKey);
    }

    // Parse the nameAlg (next 2 bytes), offset 2
    let name_alg_offset = type_offset + 2;

    // Parse the objectAttributes (next 4 bytes), offset 4
    let object_attributes_offset = name_alg_offset + 2;

    // Parse the authPolicy, offset 8
    let auth_policy_size_offset = object_attributes_offset + 4;
    let auth_policy_size = u16::from_be_bytes(
        public_area[auth_policy_size_offset..auth_policy_size_offset + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let auth_policy_offset = auth_policy_size_offset + 2;

    // Parse the parameters (TPMT_PUBLIC_PARMS), offset 8 + policy size
    let parameters_offset = auth_policy_offset + auth_policy_size;
    let symmetric = u16::from_be_bytes([
        public_area[parameters_offset],
        public_area[parameters_offset + 1],
    ]);

    let scheme_offset = if symmetric != TPM2_ALG_NULL {
        parameters_offset + 6
    } else {
        parameters_offset + 2
    };
    let scheme = u16::from_be_bytes([public_area[scheme_offset], public_area[scheme_offset + 1]]);

    let curve_id_offset = if scheme != TPM2_ALG_NULL {
        scheme_offset + 4
    } else {
        scheme_offset + 2
    };
    let curve_id = u16::from_be_bytes(
        public_area[curve_id_offset..curve_id_offset + 2]
            .try_into()
            .unwrap(),
    );

    if curve_id != TPM_ECC_NIST_P384 {
        return Err(VtpmError::EndorsementKey);
    }

    // Skip the rest of the parameters structure to get to the unique field
    let unique_offset = curve_id_offset + 4;

    // Extract X and Y coordinates from unique field
    let x_offset = unique_offset;
    let x_size = u16::from_be_bytes([public_area[x_offset], public_area[x_offset + 1]]) as usize;
    let x = public_area[x_offset + 2..x_offset + 2 + x_size].to_vec();

    let y_offset = x_offset + 2 + x_size;
    let y_size = u16::from_be_bytes([public_area[y_offset], public_area[y_offset + 1]]) as usize;
    let y = public_area[y_offset + 2..y_offset + 2 + y_size].to_vec();

    Ok((x, y))
}

pub fn provision_ek_cert(cert: &[u8]) -> Result<(), VtpmError> {
    write_cert_nv(TPM2_NV_INDEX_ECC_SECP384R1_HI_EKCERT, cert)
}

pub fn provision_ca_cert(cert: &[u8]) -> Result<(), VtpmError> {
    write_cert_nv(TPM2_NV_INDEX_VTPM_CA_CERT_CHAIN, cert)
}

fn write_cert_nv(nv_index: u32, cert: &[u8]) -> Result<(), VtpmError> {
    if cert.len() > u16::MAX as usize {
        return Err(VtpmError::EndorsementKey);
    }
    let nv_attributes: u32 = TPMA_NV_PLATFORMCREATE
        | TPMA_NV_AUTHREAD
        | TPMA_NV_OWNERREAD
        | TPMA_NV_PPREAD
        | TPMA_NV_PPWRITE
        | TPMA_NV_NO_DA
        | TPMA_NV_WRITEDEFINE;

    let mut offset = 0;
    let mut nv_index: u32 = nv_index;

    while cert.len() > offset {
        let len = if cert.len() - offset > MAX_NV_INDEX_SIZE as usize {
            MAX_NV_INDEX_SIZE as usize
        } else {
            cert.len() - offset
        };
        nv_define_space(nv_index, len as u16, nv_attributes).unwrap();
        nv_write(nv_index, &cert[offset..offset + len]).unwrap();
        offset += len;
        nv_index += 1;
    }

    Ok(())
}
