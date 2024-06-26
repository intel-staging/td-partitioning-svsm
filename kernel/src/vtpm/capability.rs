// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Jiaqi Gao <jiaqi.gao@intel.com>

use super::{
    cmd::{
        tpm2_get_capability::{get_capability, TPM_CAP_TPM_PROPERTIES},
        TpmCommandError,
    },
    VtpmError,
};
use crate::locking::SpinLock;
use core::cell::OnceCell;

const TPM_PT_NV_INDEX_MAX: u32 = 0x117;
const TPM_PT_NV_BUFFER_MAX: u32 = 0x12c;
const TPM_PT_MANUFACTURER: u32 = 0x105;
const TPM_PT_VENDOR_STRING_1: u32 = 0x106;
const TPM_PT_VENDOR_STRING_2: u32 = 0x107;
const TPM_PT_VENDOR_STRING_3: u32 = 0x108;
const TPM_PT_VENDOR_STRING_4: u32 = 0x109;
const TPM_PT_FIRMWARE_VERSION_1: u32 = 0x10b;
const TPM_PT_FIRMWARE_VERSION_2: u32 = 0x10c;

#[derive(Default, Debug, Clone, Copy)]
pub struct Tpm2Property {
    pub max_nv_index_size: u32,
    pub max_nv_buffer_size: u32,
    pub manufacturer: u32,
    pub vendor_1: u32,
    pub vendor_2: u32,
    pub vendor_3: u32,
    pub vendor_4: u32,
    pub version_1: u32,
    pub version_2: u32,
}

pub(crate) static TPM_PROPERTY: SpinLock<OnceCell<Tpm2Property>> = SpinLock::new(OnceCell::new());

pub fn tpm_property() -> Result<Tpm2Property, VtpmError> {
    // Set the handle to the global data
    Ok(*TPM_PROPERTY
        .lock()
        .get_or_init(|| get_tpm_property().expect("Failed to get TPM properties")))
}

fn get_tpm_property() -> Result<Tpm2Property, VtpmError> {
    let data =
        get_capability(TPM_CAP_TPM_PROPERTIES, 0x00000100, 0x7f).map_err(VtpmError::RunCommand)?;

    if data.len() < 9 {
        return Err(VtpmError::RunCommand(TpmCommandError::UnexpectedResponse));
    }

    // skip the more_data
    let mut offset = 1;
    // check capability. It should be TPM_CAP_TPM_PROPERTIES(0x6)
    let capability: u32 = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
    if capability != TPM_CAP_TPM_PROPERTIES {
        return Err(VtpmError::RunCommand(TpmCommandError::UnexpectedResponse));
    }

    //properties count
    offset += 4;
    let prop_count: u32 = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
    if prop_count == 0 {
        return Err(VtpmError::RunCommand(TpmCommandError::UnexpectedResponse));
    }

    // walk thru the properties
    offset += 4;
    if data.len() - offset != (prop_count * 8) as usize {
        return Err(VtpmError::RunCommand(TpmCommandError::UnexpectedResponse));
    }

    let mut properties = Tpm2Property::default();
    for _i in 0..prop_count {
        let property = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let value = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
        match property {
            TPM_PT_NV_INDEX_MAX => properties.max_nv_index_size = value,
            TPM_PT_NV_BUFFER_MAX => properties.max_nv_buffer_size = value,
            TPM_PT_MANUFACTURER => properties.manufacturer = value,
            TPM_PT_VENDOR_STRING_1 => properties.vendor_1 = value,
            TPM_PT_VENDOR_STRING_2 => properties.vendor_2 = value,
            TPM_PT_VENDOR_STRING_3 => properties.vendor_3 = value,
            TPM_PT_VENDOR_STRING_4 => properties.vendor_4 = value,
            TPM_PT_FIRMWARE_VERSION_1 => properties.version_1 = value,
            TPM_PT_FIRMWARE_VERSION_2 => properties.version_2 = value,
            _ => continue,
        }
        offset += 4;
    }

    Ok(properties)
}
