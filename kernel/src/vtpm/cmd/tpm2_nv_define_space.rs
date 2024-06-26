// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Jiaqi Gao <jiaqi.gao@intel.com>

extern crate alloc;
use super::*;
use crate::tcg2::TPM2_HASH_ALG_ID_SHA384;
use crate::vtpm::{vtpm_get_locked, MsTpmSimulatorInterface};
use alloc::{vec, vec::Vec};

const TPM2_CC_NV_DEFINE_SPACE: u32 = 0x0000012A;

pub fn nv_define_space(
    nv_index: u32,
    nv_size: u16,
    nv_attributes: u32,
) -> Result<(), TpmCommandError> {
    // Setup the NV define space command
    let command = tpm2_command_nv_define_space(nv_index, nv_size, nv_attributes)?;
    let mut length = command.len();

    // Copy the command into the request/response buffer
    let mut buffer = vec![0u8; TPM_COMMAND_MAX_BUFFER_SIZE];
    buffer[..length].copy_from_slice(&command);

    // Execute the TPM command
    vtpm_get_locked()
        .send_tpm_command(&mut buffer, &mut length, 0)
        .map_err(|_| TpmCommandError::Simulator)?;

    // Validate and parse the TPM response
    tpm2_response_nv_define_space(&buffer[..length])
}

fn tpm2_command_nv_define_space(
    nv_index: u32,
    nv_size: u16,
    nv_attributes: u32,
) -> Result<Vec<u8>, TpmCommandError> {
    let mut public_info = Vec::new();
    let mut command: Vec<u8> = Vec::new();

    // NV Index
    public_info.extend(&nv_index.to_be_bytes());
    // Alg Hash
    public_info.extend(&TPM2_HASH_ALG_ID_SHA384.to_be_bytes());
    // NV Attributes
    public_info.extend(&nv_attributes.to_be_bytes());
    // Auth Policy
    public_info.extend(&0u16.to_be_bytes());
    // Data Size
    public_info.extend(&nv_size.to_be_bytes());

    // TPM header
    command.extend(&TPM_ST_SESSIONS.to_be_bytes());
    command.extend(&[0u8, 0u8, 0u8, 0u8]); // Placeholder for command size
    command.extend(&TPM2_CC_NV_DEFINE_SPACE.to_be_bytes());

    // authHandle
    command.extend(&TPM2_RH_PLATFORM.to_be_bytes());

    // Authorization session
    command.extend(&[0u8, 0u8, 0u8, 9u8]); // Authorization size
    command.extend(&TPM2_RS_PW.to_be_bytes()); // Session handle
    command.extend(&[0u8, 0u8]); // Nonce
    command.extend(&[0u8]); // Session attributes
    command.extend(&[0u8, 0u8]); // hmac

    command.extend_from_slice(&0_u16.to_be_bytes());
    // Public parameters of the NV area
    command.extend(&(public_info.len() as u16).to_be_bytes()); // Size of publicInfo
    command.extend(&public_info); // publicInfo

    // Update command size
    let length = command.len() as u32;
    command[2..6].copy_from_slice(&length.to_be_bytes());

    Ok(command)
}

fn tpm2_response_nv_define_space(response: &[u8]) -> Result<(), TpmCommandError> {
    if response.len() < TPM2_RESPONSE_HEADER_SIZE {
        return Err(TpmCommandError::UnexpectedResponse);
    }

    // Safety: we have checked the length of the response
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    if rc != TPM_RC_SUCCESS {
        return Err(TpmCommandError::ResponseError(rc));
    }

    Ok(())
}
