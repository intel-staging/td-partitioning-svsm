// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Jiaqi Gao <jiaqi.gao@intel.com>

extern crate alloc;

use super::*;
use crate::vtpm::{vtpm_get_locked, MsTpmSimulatorInterface};
use alloc::{vec, vec::Vec};

pub const TPM_CAP_TPM_PROPERTIES: u32 = 0x00000006;
const TPM2_CC_GET_CAPABILITY: u32 = 0x0000017A;

pub fn get_capability(
    capability: u32,
    property: u32,
    property_count: u32,
) -> Result<Vec<u8>, TpmCommandError> {
    // Setup the sign command
    let command = tpm2_command_get_capability(capability, property, property_count)?;
    let mut length = command.len();

    // Copy the command into the request/response buffer
    let mut buffer = vec![0u8; TPM_COMMAND_MAX_BUFFER_SIZE];
    buffer[..length].copy_from_slice(&command);

    // Execute the TPM command
    vtpm_get_locked()
        .send_tpm_command(&mut buffer, &mut length, 0)
        .map_err(|_| TpmCommandError::Simulator)?;

    // Validate and parse the TPM response
    tpm2_get_capability_response(&buffer[..length])
}

pub fn tpm2_command_get_capability(
    capability: u32,
    property: u32,
    property_count: u32,
) -> Result<Vec<u8>, TpmCommandError> {
    let mut command: Vec<u8> = Vec::new();

    // TPM header
    command.extend(&TPM_ST_NO_SESSIONS.to_be_bytes());
    command.extend(&[0u8, 0u8, 0u8, 0u8]); // Placeholder for command size
    command.extend(&TPM2_CC_GET_CAPABILITY.to_be_bytes());

    // capability: group selection; determines the format of the response
    command.extend(&capability.to_be_bytes());

    // property: further definition of information
    command.extend(&property.to_be_bytes());

    // propertyCount: number of properties of the indicated type to return
    command.extend(&property_count.to_be_bytes());

    // Update command size
    let length = command.len() as u32;
    command[2..6].copy_from_slice(&length.to_be_bytes());

    Ok(command)
}

pub fn tpm2_get_capability_response(response: &[u8]) -> Result<Vec<u8>, TpmCommandError> {
    if response.len() < TPM2_RESPONSE_HEADER_SIZE {
        return Err(TpmCommandError::UnexpectedResponse);
    }

    // Safety: we have checked the length of the response
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    if rc != TPM_RC_SUCCESS {
        return Err(TpmCommandError::ResponseError(rc));
    }

    Ok(response[TPM2_RESPONSE_HEADER_SIZE..].to_vec())
}
