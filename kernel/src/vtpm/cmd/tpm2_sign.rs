// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Jiaqi Gao <jiaqi.gao@intel.com>

extern crate alloc;

use super::*;
use crate::vtpm::{vtpm_get_locked, MsTpmSimulatorInterface};
use alloc::{vec, vec::Vec};

const TPM2_CC_SIGN: u32 = 0x0000015D;

pub fn sign(
    key_handle: u32,
    digest: &[u8],
    sig_scheme_selector: u16,
    sig_scheme_param: u16,
) -> Result<Vec<u8>, TpmCommandError> {
    // Setup the sign command
    let command = tpm2_command_sign(key_handle, digest, sig_scheme_selector, sig_scheme_param)?;
    let mut length = command.len();

    // Copy the command into the request/response buffer
    let mut buffer = vec![0u8; TPM_COMMAND_MAX_BUFFER_SIZE];
    buffer[..length].copy_from_slice(&command);

    // Execute the TPM command
    vtpm_get_locked()
        .send_tpm_command(&mut buffer, &mut length, 0)
        .map_err(|_| TpmCommandError::Simulator)?;

    // Validate and parse the TPM response
    tpm2_sign_response(&buffer[..length])
}

pub fn tpm2_command_sign(
    key_handle: u32,
    digest: &[u8],
    scheme_selector: u16,
    scheme_param: u16,
) -> Result<Vec<u8>, TpmCommandError> {
    let mut command: Vec<u8> = Vec::new();

    // TPM header
    command.extend(&TPM_ST_SESSIONS.to_be_bytes());
    command.extend(&[0u8, 0u8, 0u8, 0u8]); // Placeholder for command size
    command.extend(&TPM2_CC_SIGN.to_be_bytes());

    // Key handle
    command.extend(&key_handle.to_be_bytes());

    // Authorization session
    command.extend(&[0u8, 0u8, 0u8, 9u8]); // Authorization size
    command.extend(&TPM2_RS_PW.to_be_bytes()); // Session handle
    command.extend(&[0u8, 0u8]); // Nonce
    command.extend(&[0u8]); // Session attributes
    command.extend(&[0u8, 0u8]); // hmac

    // TPM2B_DIGEST
    command.extend(&(digest.len() as u16).to_be_bytes());
    command.extend(digest);

    // Signature scheme
    command.extend_from_slice(&scheme_selector.to_be_bytes());
    command.extend_from_slice(&scheme_param.to_be_bytes());

    // Hash Check
    command.extend(&[0x80, 0x24]);
    command.extend(&TPM2_RH_ENDORSEMENT.to_be_bytes());
    command.extend(&0u16.to_be_bytes());

    // Update command size
    let length = command.len() as u32;
    command[2..6].copy_from_slice(&length.to_be_bytes());

    Ok(command)
}

pub fn tpm2_sign_response(response: &[u8]) -> Result<Vec<u8>, TpmCommandError> {
    if response.len() < TPM2_RESPONSE_HEADER_SIZE {
        return Err(TpmCommandError::UnexpectedResponse);
    }

    // Safety: we have checked the length of the response
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    if rc != TPM_RC_SUCCESS {
        return Err(TpmCommandError::ResponseError(rc));
    }

    if response.len() < TPM2_RESPONSE_HEADER_SIZE + 4 {
        return Err(TpmCommandError::UnexpectedResponse);
    }
    // Safety: we have checked the length of the response
    let param_size = u32::from_be_bytes(response[10..14].try_into().unwrap()) as usize;

    if response.len() < TPM2_RESPONSE_HEADER_SIZE + 4 + param_size {
        return Err(TpmCommandError::UnexpectedResponse);
    }

    let param_offset = TPM2_RESPONSE_HEADER_SIZE + 4;
    Ok(response[param_offset..param_offset + param_size].to_vec())
}
