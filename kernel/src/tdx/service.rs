use super::{error::TdxError, gmem::accept_guest_mem, measurement::handle_vtpm_request};
use crate::{
    address::{Address, GuestPhysAddr},
    fw_meta::Uuid,
    mm::{PerCPUPageMappingGuard, PAGE_SIZE},
};
use core::{
    mem::size_of,
    ptr::addr_of_mut,
    slice::{from_raw_parts, from_raw_parts_mut},
    str::FromStr,
};

const SERVICE_L1VTPM_GUID: &str = "766cf580-8dc3-4cea-a94e-e5424da1da56";

#[repr(C)]
#[derive(Debug, Default)]
pub(crate) struct TdVmcallServiceCommandHeader {
    guid: [u8; 16],
    length: u32,
    reserved: u32,
}

impl TdVmcallServiceCommandHeader {
    fn read_from_bytes(bytes: &[u8]) -> Result<Self, TdxError> {
        if bytes.len() < size_of::<Self>() {
            return Err(TdxError::Service);
        }

        let mut header = Self::default();
        unsafe {
            from_raw_parts_mut(addr_of_mut!(header) as *mut u8, size_of::<Self>())
                .copy_from_slice(&bytes[..size_of::<Self>()])
        }
        Ok(header)
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub(crate) struct TdVmcallServiceResponseHeader {
    guid: [u8; 16],
    length: u32,
    status: u32,
}

impl TdVmcallServiceResponseHeader {
    fn read_from_bytes(bytes: &[u8]) -> Result<Self, TdxError> {
        if bytes.len() < size_of::<Self>() {
            return Err(TdxError::Service);
        }

        let mut header = Self::default();
        unsafe {
            from_raw_parts_mut(addr_of_mut!(header) as *mut u8, size_of::<Self>())
                .copy_from_slice(&bytes[..size_of::<Self>()])
        }
        Ok(header)
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { from_raw_parts(self as *const _ as *const u8, size_of::<Self>()) }
    }
}

fn accept_and_create_mapping(
    start: GuestPhysAddr,
    size: usize,
) -> Result<PerCPUPageMappingGuard, TdxError> {
    let end = start.checked_add(size).ok_or(TdxError::Service)?;
    let _ = accept_guest_mem(start, end)?;
    // Map the host physical address
    let cmd_mapping =
        PerCPUPageMappingGuard::create(start.to_host_phys_addr(), end.to_host_phys_addr(), 0)
            .map_err(|_| TdxError::Service)?;

    Ok(cmd_mapping)
}

pub fn handle_vmcall_service(
    cmd_addr: GuestPhysAddr,
    resp_addr: GuestPhysAddr,
) -> Result<(), TdxError> {
    let cmd_mapping = accept_and_create_mapping(cmd_addr, PAGE_SIZE)?;
    let cmd = unsafe { from_raw_parts(cmd_mapping.virt_addr().as_ptr::<u8>(), PAGE_SIZE) };

    let resp_mapping = accept_and_create_mapping(resp_addr, PAGE_SIZE)?;
    let resp =
        unsafe { from_raw_parts_mut(resp_mapping.virt_addr().as_mut_ptr::<u8>(), PAGE_SIZE) };

    // Deserialize the command and response header and check the GUID.
    let cmd_hdr = TdVmcallServiceCommandHeader::read_from_bytes(cmd)?;
    let mut resp_hdr = TdVmcallServiceResponseHeader::read_from_bytes(resp)?;
    if cmd_hdr.guid != resp_hdr.guid {
        return Err(TdxError::Service);
    }
    // Remap the response buffer with actual response length.
    let resp_mapping = accept_and_create_mapping(resp_addr, resp_hdr.length as usize)?;
    let resp = unsafe {
        from_raw_parts_mut(
            resp_mapping.virt_addr().as_mut_ptr::<u8>(),
            resp_hdr.length as usize,
        )
    };

    if Uuid::from(&cmd_hdr.guid)
        == Uuid::from_str(SERVICE_L1VTPM_GUID).map_err(|_| TdxError::Service)?
    {
        let resp_size = handle_vtpm_request(cmd, resp).map_err(|_| TdxError::Service)?;
        // Set the length field of the reponse buffer
        resp_hdr.length = (resp_size + size_of::<TdVmcallServiceResponseHeader>()) as u32;
        resp[..size_of::<TdVmcallServiceResponseHeader>()].copy_from_slice(resp_hdr.as_bytes());
    } else {
        return Err(TdxError::Service);
    }
    Ok(())
}
