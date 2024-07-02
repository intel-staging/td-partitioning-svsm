// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2024 Intel Corporation
//
// Author: Jiaqi Gao <jiaqi.gao@intel.com>

pub mod tpm2_create_loaded;
pub mod tpm2_create_primary;
pub mod tpm2_evict_control;
pub mod tpm2_flush_context;
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

// Object attributes
pub const TPMA_OBJ_FIXED_TPM: u32 = 0x00000002;
pub const TPMA_OBJ_RESTRICTED: u32 = 0x00010000;
pub const TPMA_OBJ_FIXED_PERSISTENT: u32 = 0x00020000;
pub const TPMA_OBJ_SENSITIVE_DATA_ORIGIN: u32 = 0x00080000;
pub const TPMA_OBJ_USER_WITH_AUTH: u32 = 0x40000;
pub const TPMA_OBJECT_FIXEDPARENT: u32 = 0x00000010;
pub const TPMA_OBJECT_SENSITIVEDATAORIGIN: u32 = 0x00000020;
pub const TPMA_OBJECT_USERWITHAUTH: u32 = 0x00000040;
pub const TPMA_OBJECT_ADMINWITHPOLICY: u32 = 0x00000080;
pub const TPMA_OBJECT_RESTRICTED: u32 = 0x00010000;
pub const TPMA_OBJECT_DECRYPT: u32 = 0x00020000;
pub const TPMA_OBJECT_NO_DA: u32 = 0x00000400;
pub const TPMA_OBJECT_SIGN: u32 = 0x00040000;

pub const TPM_ECC_NIST_P384: u16 = 0x0004;
pub const TPM2_ALG_AES: u16 = 0x0006;
pub const TPM_ALG_SHA384: u16 = 0x000C;
pub const TPM2_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_ECDSA: u16 = 0x0018;
pub const TPM_ALG_ECC: u16 = 0x0023;
pub const TPM2_ALG_CFB: u16 = 0x0043;

pub const TPMA_NV_PLATFORMCREATE: u32 = 0x40000000;
pub const TPMA_NV_AUTHREAD: u32 = 0x40000;
pub const TPMA_NV_NO_DA: u32 = 0x2000000;
pub const TPMA_NV_PPWRITE: u32 = 0x1;
pub const TPMA_NV_PPREAD: u32 = 0x10000;
pub const TPMA_NV_OWNERREAD: u32 = 0x20000;
pub const TPMA_NV_WRITEDEFINE: u32 = 0x2000;

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
