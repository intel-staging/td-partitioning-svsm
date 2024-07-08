// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Hank Ouyang <hank.ouyang@intel.com>

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::{
    tdx::error::TdxError,
    vtpm::{vtpm_get_locked, MsTpmSimulatorInterface, VtpmError},
};

use super::{
    TPM2_CC_CONTESTLOAD_HEAD, TPM2_CC_CONTEXSAVE_HEAD, TPM2_CC_CREATE_PRIMARY,
    TPM2_CC_FLUSHCONTEXT_HEAD, TPM2_CC_GETAP_CMD, TPM2_CC_GETRANDOM_CMD,
    TPM2_CC_STARTAUTHSESSION_EK, TPM2_CC_STARTAUTHSESSION_ENDORSEMENT,
    TPM2_CC_STARTAUTHSESSION_OWNER, TPM_COMMAND_MAX_BUFFER_SIZE,
};

pub const HANDLE_AUTH: [u8; 0x4] = [0x80, 0x00, 0x00, 0x00];
pub const HANDLE_OWNER: [u8; 0x4] = [0x02, 0x00, 0x00, 0x00];
pub const HANDLE_ENDORSEMENT: [u8; 0x4] = [0x02, 0x00, 0x00, 0x01];
pub const HANDLE_EK: [u8; 0x4] = [0x02, 0x00, 0x00, 0x02];

fn tpm2_command_send(command: &[u8]) -> Result<Vec<u8>, VtpmError> {
    // Setup the command
    let mut length = command.len();

    // Copy the command into the request/response buffer
    let mut buffer = vec![0u8; TPM_COMMAND_MAX_BUFFER_SIZE];
    buffer[..length].copy_from_slice(&command);

    // Execute the TPM command
    vtpm_get_locked()
        .send_tpm_command(&mut buffer, &mut length, 0)
        .map_err(|_| VtpmError::EndorsementKey)?;

    // Return the TPM response
    Ok(buffer)
}

fn tpm2_command_getrandom() -> Result<Vec<u8>, VtpmError> {
    // Setup the command
    let command = TPM2_CC_GETRANDOM_CMD;
    let mut length = command.len();

    // Copy the command into the request/response buffer
    let mut buffer = vec![0u8; TPM_COMMAND_MAX_BUFFER_SIZE];
    buffer[..length].copy_from_slice(&command);

    // Execute the TPM command
    vtpm_get_locked()
        .send_tpm_command(&mut buffer, &mut length, 0)
        .map_err(|_| VtpmError::EndorsementKey)?;

    // Return the TPM response
    let nonce = buffer[12..20].to_vec();

    Ok(nonce)
}

fn tpm2_command_getcap() -> Result<Vec<u8>, VtpmError> {
    // Setup the command
    let command = TPM2_CC_GETAP_CMD;
    let mut length = command.len();

    // Copy the command into the request/response buffer
    let mut buffer = vec![0u8; TPM_COMMAND_MAX_BUFFER_SIZE];
    buffer[..length].copy_from_slice(&command);

    // Execute the TPM command
    vtpm_get_locked()
        .send_tpm_command(&mut buffer, &mut length, 0)
        .map_err(|_| VtpmError::EndorsementKey)?;

    // Return the TPM response
    Ok(buffer)
}

fn tpm2_command_contextsave(handle: &[u8]) -> Result<Vec<u8>, VtpmError> {
    // Setup the command
    let command = TPM2_CC_CONTEXSAVE_HEAD;
    let mut length = command.len();

    // Copy the command into the request/response buffer
    let mut buffer = vec![0u8; TPM_COMMAND_MAX_BUFFER_SIZE];
    buffer[..length].copy_from_slice(&command);
    // Handle size is 4;
    buffer[length..length + 4].copy_from_slice(&handle);
    length += 4;

    // Execute the TPM command
    vtpm_get_locked()
        .send_tpm_command(&mut buffer, &mut length, 0)
        .map_err(|_| VtpmError::EndorsementKey)?;

    // Return the TPM response
    let buf_length: usize =
        u32::from_be_bytes([buffer[2], buffer[3], buffer[4], buffer[5]]) as usize;
    let context = buffer[10..buf_length].to_vec();

    Ok(context)
}

fn tpm2_command_contextload(context: &[u8]) -> Result<Vec<u8>, VtpmError> {
    // Setup the command
    let command = TPM2_CC_CONTESTLOAD_HEAD;
    let length = command.len();
    // Copy the command into the request/response buffer
    let mut buffer = vec![0u8; TPM_COMMAND_MAX_BUFFER_SIZE];
    buffer[..length].copy_from_slice(&command);
    buffer[length..length + context.len()].copy_from_slice(&context);

    // Update cmd size
    buffer.splice(2..6, ((length + context.len()) as u32).to_be_bytes());

    let mut buf_length: usize =
        u32::from_be_bytes([buffer[2], buffer[3], buffer[4], buffer[5]]) as usize;

    // Execute the TPM command
    vtpm_get_locked()
        .send_tpm_command(&mut buffer, &mut buf_length, 0)
        .map_err(|_| VtpmError::EndorsementKey)?;

    // Return the TPM response
    Ok(buffer)
}

fn tpm2_command_flushcontext(handle: &[u8]) -> Result<Vec<u8>, VtpmError> {
    // Setup the command
    let command = TPM2_CC_FLUSHCONTEXT_HEAD;
    let mut length = command.len();

    // Copy the command into the request/response buffer
    let mut buffer = vec![0u8; TPM_COMMAND_MAX_BUFFER_SIZE];
    buffer[..length].copy_from_slice(&command);

    // Handle size is 4;
    buffer[length..length + 4].copy_from_slice(&handle);
    length += 4;

    // Execute the TPM command
    vtpm_get_locked()
        .send_tpm_command(&mut buffer, &mut length, 0)
        .map_err(|_| VtpmError::EndorsementKey)?;

    // Return the TPM response
    Ok(buffer)
}

fn tpm_tools_createek_sequence() -> Result<(), VtpmError> {
    tpm2_command_getrandom()?;
    tpm2_command_getcap()?;
    tpm2_command_send(&TPM2_CC_STARTAUTHSESSION_OWNER)?;
    let context_owner = tpm2_command_contextsave(&HANDLE_OWNER)?;
    tpm2_command_contextload(&context_owner[..])?;
    tpm2_command_getcap()?;
    let context_owner = tpm2_command_contextsave(&HANDLE_OWNER)?;
    tpm2_command_contextload(&context_owner[..])?;
    tpm2_command_send(&TPM2_CC_STARTAUTHSESSION_ENDORSEMENT)?;
    let context_owner = tpm2_command_contextsave(&HANDLE_OWNER)?;
    let context_endorsement = tpm2_command_contextsave(&HANDLE_ENDORSEMENT)?;
    tpm2_command_contextload(&context_owner[..])?;
    tpm2_command_contextload(&context_endorsement[..])?;
    tpm2_command_getcap()?;
    let context_owner = tpm2_command_contextsave(&HANDLE_OWNER)?;
    let context_endorsement = tpm2_command_contextsave(&HANDLE_ENDORSEMENT)?;
    tpm2_command_contextload(&context_owner[..])?;
    tpm2_command_contextload(&context_endorsement[..])?;
    tpm2_command_send(&TPM2_CC_STARTAUTHSESSION_EK)?;
    let context_owner = tpm2_command_contextsave(&HANDLE_OWNER)?;
    let context_endorsement = tpm2_command_contextsave(&HANDLE_ENDORSEMENT)?;
    let context_ek = tpm2_command_contextsave(&HANDLE_EK)?;
    tpm2_command_contextload(&context_owner[..])?;
    tpm2_command_contextload(&context_endorsement[..])?;
    tpm2_command_contextload(&context_ek[..])?;

    log::info!("Create primary\n");
    tpm2_command_send(&TPM2_CC_CREATE_PRIMARY)?;

    let context_auth = tpm2_command_contextsave(&HANDLE_AUTH)?;
    tpm2_command_flushcontext(&HANDLE_AUTH)?;
    let context_owner = tpm2_command_contextsave(&HANDLE_OWNER)?;
    let context_endorsement = tpm2_command_contextsave(&HANDLE_ENDORSEMENT)?;
    let context_ek = tpm2_command_contextsave(&HANDLE_EK)?;
    tpm2_command_contextload(&context_auth[..])?;
    tpm2_command_contextload(&context_owner[..])?;
    tpm2_command_contextload(&context_endorsement[..])?;
    tpm2_command_contextload(&context_ek[..])?;
    tpm2_command_contextsave(&HANDLE_AUTH)?;
    let context_auth = tpm2_command_contextsave(&HANDLE_AUTH)?;
    tpm2_command_flushcontext(&HANDLE_AUTH)?;
    let context_owner = tpm2_command_contextsave(&HANDLE_OWNER)?;
    let context_endorsement = tpm2_command_contextsave(&HANDLE_ENDORSEMENT)?;
    let context_ek = tpm2_command_contextsave(&HANDLE_EK)?;
    tpm2_command_contextload(&context_auth[..])?;
    tpm2_command_contextload(&context_owner[..])?;
    tpm2_command_contextload(&context_endorsement[..])?;
    tpm2_command_contextload(&context_ek[..])?;
    tpm2_command_flushcontext(&HANDLE_OWNER)?;
    tpm2_command_contextsave(&HANDLE_AUTH)?;
    tpm2_command_flushcontext(&HANDLE_AUTH)?;
    let context_owner = tpm2_command_contextsave(&HANDLE_OWNER)?;
    let context_endorsement = tpm2_command_contextsave(&HANDLE_ENDORSEMENT)?;
    let context_ek = tpm2_command_contextsave(&HANDLE_EK)?;
    tpm2_command_contextload(&context_owner[..])?;
    tpm2_command_contextload(&context_endorsement[..])?;
    tpm2_command_contextload(&context_ek[..])?;
    tpm2_command_flushcontext(&HANDLE_ENDORSEMENT)?;
    tpm2_command_contextsave(&HANDLE_AUTH)?;
    tpm2_command_flushcontext(&HANDLE_AUTH)?;
    let context_endorsement = tpm2_command_contextsave(&HANDLE_ENDORSEMENT)?;
    let context_ek = tpm2_command_contextsave(&HANDLE_EK)?;
    tpm2_command_contextload(&context_endorsement[..])?;
    tpm2_command_contextload(&context_ek[..])?;
    tpm2_command_flushcontext(&HANDLE_EK)?;
    tpm2_command_contextsave(&HANDLE_AUTH)?;
    tpm2_command_flushcontext(&HANDLE_AUTH)?;
    tpm2_command_contextsave(&HANDLE_EK)?;
    Ok(())
}

pub fn test_createek_flow() -> Result<(), TdxError> {
    for n in 1..10 {
        log::info!("test round: {:?}\n", n);
        tpm_tools_createek_sequence().expect("Failed to execute createek flow!");
    }
    Ok(())
}
