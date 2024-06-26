// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Jiaqi Gao <jiaqi.gao@intel.com>

extern crate alloc;

use super::*;
use crate::vtpm::{vtpm_get_locked, MsTpmSimulatorInterface};
use alloc::{vec, vec::Vec};

const TPM2_CC_CREATE_LOADED: u32 = 0x00000191;

#[derive(Debug, Clone)]
pub struct Tpm2CreateLoadedResponse {
    pub handle: u32,
    pub public_area: Vec<u8>,
}

pub fn create_loaded(
    parent_handle: u32,
    public_area: &[u8],
) -> Result<Tpm2CreateLoadedResponse, TpmCommandError> {
    // Setup the create loaded command
    let command = tpm2_command_create_loaded(parent_handle, public_area)?;
    let mut length = command.len();

    // Copy the command into the request/response buffer
    let mut buffer = vec![0u8; TPM_COMMAND_MAX_BUFFER_SIZE];
    buffer[..length].copy_from_slice(&command);

    // Execute the TPM command
    vtpm_get_locked()
        .send_tpm_command(&mut buffer, &mut length, 0)
        .map_err(|_| TpmCommandError::Simulator)?;

    // Validate and parse the TPM response
    tpm2_response_create_loaded(&buffer[..length])
}

fn tpm2_command_create_loaded(
    parent_handle: u32,
    public_area: &[u8],
) -> Result<Vec<u8>, TpmCommandError> {
    let mut command = Vec::new();

    // TPM header
    command.extend(&TPM_ST_SESSIONS.to_be_bytes());
    command.extend(&[0u8, 0u8, 0u8, 0u8]); // Placeholder for command size
    command.extend(&TPM2_CC_CREATE_LOADED.to_be_bytes());

    // Parent handle
    command.extend(&parent_handle.to_be_bytes());

    // Authorization session
    command.extend(&[0u8, 0u8, 0u8, 9u8]); // Authorization size
    command.extend(&TPM2_RS_PW.to_be_bytes()); // Session handle
    command.extend(&[0u8, 0u8]); // Nonce
    command.extend(&[0u8]); // Session attributes
    command.extend(&[0u8, 0u8]); // hmac

    // TPM2B_SENSITIVE_CREATE (empty auth, no additional data)
    command.extend(&[0u8, 4u8]); // Size
    command.extend(&[0u8, 0u8]); // User auth size
    command.extend(&[0u8, 0u8]); // Data size

    // TPM2B_PUBLIC
    command.extend(&(public_area.len() as u16).to_be_bytes());
    command.extend(public_area);

    // Update command size
    let length = command.len() as u32;
    command[2..6].copy_from_slice(&length.to_be_bytes());

    Ok(command)
}

fn tpm2_response_create_loaded(
    response: &[u8],
) -> Result<Tpm2CreateLoadedResponse, TpmCommandError> {
    if response.len() < TPM2_RESPONSE_HEADER_SIZE {
        return Err(TpmCommandError::UnexpectedResponse);
    }

    // Safety: we have checked the length of the response
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    if rc != TPM_RC_SUCCESS {
        return Err(TpmCommandError::ResponseError(rc));
    }

    let handle_offset = TPM2_RESPONSE_HEADER_SIZE;
    let handle = u32::from_be_bytes([
        response[handle_offset],
        response[handle_offset + 1],
        response[handle_offset + 2],
        response[handle_offset + 3],
    ]);
    let _parameter_size = u32::from_be_bytes([
        response[handle_offset + 4],
        response[handle_offset + 5],
        response[handle_offset + 6],
        response[handle_offset + 7],
    ]);
    let sensitive_offset = handle_offset + 8;
    let sensitive_area_size =
        u16::from_be_bytes([response[sensitive_offset], response[sensitive_offset + 1]]);
    let public_offset = sensitive_offset + 2 + sensitive_area_size as usize;
    let public_area_size =
        u16::from_be_bytes([response[public_offset], response[public_offset + 1]]);
    let public_area =
        response[public_offset + 2..public_offset + 2 + public_area_size as usize].to_vec();

    Ok(Tpm2CreateLoadedResponse {
        handle,
        public_area,
    })
}
