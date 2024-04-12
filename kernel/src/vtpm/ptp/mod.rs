// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 Intel Corporation.
//

use crate::locking::SpinLock;
use crb::{Result, Tpm};

pub mod crb;

pub const TPM_START: u64 = 0xfed4_0000;
pub const TPM_SIZE: u64 = 0x1000;
pub const TPM_CRB_BUFFER_MAX: usize = 3968; // 0x1_000 - 0x80

static TPM: SpinLock<Tpm> = SpinLock::new(Tpm::new());

pub fn vtpm_range() -> (u64, u64) {
    (TPM_START, TPM_START + TPM_SIZE)
}

pub fn init() -> Result<()> {
    TPM.lock().init()
}

pub fn tpm_mmio_read(addr: u64, size: usize) -> u64 {
    let mut data = [0u8; 8];
    TPM.lock().mmio_read(addr - TPM_START, &mut data[..size]);
    u64::from_le_bytes(data)
}

pub fn tpm_mmio_write(addr: u64, data: u64, size: usize) {
    let input = data.to_le_bytes();
    TPM.lock().mmio_write(addr - TPM_START, &input[..size])
}
