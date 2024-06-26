// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

extern crate alloc;

use super::*;
use crate::tcg2::TpmlDigestValues;
use crate::vtpm::{vtpm_get_locked, MsTpmSimulatorInterface};
use alloc::{vec, vec::Vec};

const TPM2_CC_PCR_EXTEND: u32 = 0x182;

pub fn pcr_extend(pcr_index: u32, digests: &TpmlDigestValues) -> Result<(), TpmCommandError> {
    // Setup the PCR extend command
    let command = tpm2_command_pcr_extend(pcr_index, digests)?;
    let mut length = command.len();

    // Copy the command into the request/response buffer
    let mut buffer = vec![0u8; TPM_COMMAND_MAX_BUFFER_SIZE];
    buffer[..length].copy_from_slice(&command);

    // Execute the TPM command
    vtpm_get_locked()
        .send_tpm_command(&mut buffer, &mut length, 0)
        .map_err(|_| TpmCommandError::Simulator)?;

    // Validate and parse the TPM response
    tpm2_response_pcr_extend(&buffer[..length])
}

fn tpm2_command_pcr_extend(
    pcr_index: u32,
    digests: &TpmlDigestValues,
) -> Result<Vec<u8>, TpmCommandError> {
    let mut command: Vec<u8> = Vec::new();

    // TPM header
    command.extend(&TPM_ST_SESSIONS.to_be_bytes());
    command.extend(&[0u8, 0u8, 0u8, 0u8]); // Placeholder for command size
    command.extend(&TPM2_CC_PCR_EXTEND.to_be_bytes());

    // PCR handle
    command.extend(&pcr_index.to_be_bytes());

    // Authorization session
    command.extend(&[0u8, 0u8, 0u8, 9u8]); // Authorization size
    command.extend(&TPM2_RS_PW.to_be_bytes()); // Session handle
    command.extend(&[0u8, 0u8]); // Nonce
    command.extend(&[0u8]); // Session attributes
    command.extend(&[0u8, 0u8]); // hmac

    // Digest count
    command.extend(&digests.count.to_be_bytes());

    // Digest value
    let size = digests.size().ok_or(TpmCommandError::SetupCommand)?;
    let mut buffer = vec![0u8; size];
    digests.write_be_bytes(buffer.as_mut_slice());
    command.extend(buffer);

    // Update command size
    let length = command.len() as u32;
    command[2..6].copy_from_slice(&length.to_be_bytes());

    Ok(command)
}

fn tpm2_response_pcr_extend(response: &[u8]) -> Result<(), TpmCommandError> {
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
