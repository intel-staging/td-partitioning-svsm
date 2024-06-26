// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2024 Intel Corporation
//
// Author: Jiaqi Gao <jiaqi.gao@intel.com>

pub mod tpm2_create_loaded;
pub mod tpm2_create_primary;
pub mod tpm2_evict_control;
pub mod tpm2_get_capability;
pub mod tpm2_nv_define_space;
pub mod tpm2_nv_write;
pub mod tpm2_pcr_extend;
pub mod tpm2_sign;
pub mod tpm2_startup;

pub const TPM2_COMMAND_HEADER_SIZE: usize = 10;
pub const TPM2_RESPONSE_HEADER_SIZE: usize = 10;
pub const TPM_COMMAND_MAX_BUFFER_SIZE: usize = 0x1000;

pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;
pub const TPM_RC_SUCCESS: u32 = 0;

pub const TPM2_RH_OWNER: u32 = 0x40000001;
pub const TPM2_RH_ENDORSEMENT: u32 = 0x4000000B;
pub const TPM2_RH_PLATFORM: u32 = 0x4000000C;
pub const TPM2_RS_PW: u32 = 0x40000009;

pub const TPM_SU_CLEAR: u16 = 0x0000;
pub const TPM_SU_STATE: u16 = 0x0001;

#[derive(Debug, Clone, Copy)]
pub enum TpmCommandError {
    // TPM backend simulator returns error
    Simulator,
    // Failed to setup command buffer
    SetupCommand,
    // TPM returns unexpected reponse
    UnexpectedResponse,
    // TPM returns error code
    ResponseError(u32),
}
