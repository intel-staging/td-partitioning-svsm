// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Jiaqi Gao <jiaqi.gao@intel.com>

extern crate alloc;
use super::*;
use crate::vtpm::{vtpm_get_locked, MsTpmSimulatorInterface};
use alloc::{vec, vec::Vec};

const TPM2_CC_EVICTCONTROL: u32 = 0x00000120;

pub fn evict_control(object_handle: u32, persistent_handle: u32) -> Result<(), TpmCommandError> {
    // Setup the NV define space command
    let command = tpm2_command_evict_control(object_handle, persistent_handle)?;
    let mut length = command.len();

    // Copy the command into the request/response buffer
    let mut buffer = vec![0u8; TPM_COMMAND_MAX_BUFFER_SIZE];
    buffer[..length].copy_from_slice(&command);

    // Execute the TPM command
    vtpm_get_locked()
        .send_tpm_command(&mut buffer, &mut length, 0)
        .map_err(|_| TpmCommandError::Simulator)?;

    // Validate and parse the TPM response
    tpm2_response_evict_control(&buffer[..length])
}

fn tpm2_command_evict_control(
    object_handle: u32,
    persistent_handle: u32,
) -> Result<Vec<u8>, TpmCommandError> {
    let mut command: Vec<u8> = Vec::new();

    // TPM header
    command.extend(&TPM_ST_SESSIONS.to_be_bytes());
    command.extend(&[0u8, 0u8, 0u8, 0u8]); // Placeholder for command size
    command.extend(&TPM2_CC_EVICTCONTROL.to_be_bytes());

    // authHandle
    command.extend(&TPM2_RH_OWNER.to_be_bytes());

    // Object handle
    command.extend(&object_handle.to_be_bytes());

    // Authorization session
    command.extend(&[0u8, 0u8, 0u8, 9u8]); // Authorization size
    command.extend(&TPM2_RS_PW.to_be_bytes()); // Session handle
    command.extend(&[0u8, 0u8]); // Nonce
    command.extend(&[0u8]); // Session attributes
    command.extend(&[0u8, 0u8]); // hmac

    // Persistent handle
    command.extend(&persistent_handle.to_be_bytes());

    // Update command size
    let length = command.len() as u32;
    command[2..6].copy_from_slice(&length.to_be_bytes());

    Ok(command)
}

fn tpm2_response_evict_control(response: &[u8]) -> Result<(), TpmCommandError> {
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
