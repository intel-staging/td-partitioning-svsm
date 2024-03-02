// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::acpi::tables::ACPICPUInfo;
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::control_regs::{cr0_init, cr4_init};
use crate::cpu::efer::efer_init;
use crate::cpu::features::{cpu_type, is_tdx};
use crate::cpu::gdt;
use crate::cpu::ghcb::current_ghcb;
use crate::cpu::idt::idt;
use crate::cpu::percpu::{this_cpu_mut, PerCpu};
use crate::cpu::vmsa::init_svsm_vmsa;
use crate::mm::alloc::{allocate_pages, free_page};
use crate::mm::PerCPUPageMappingGuard;
use crate::task::schedule_init;
use crate::types::{CpuType, PAGE_SIZE};
use crate::utils::immut_after_init::ImmutAfterInitCell;
use core::arch::asm;
use core::arch::x86_64::_mm_sfence;

static NR_CPUS: ImmutAfterInitCell<u64> = ImmutAfterInitCell::uninit();

pub fn init_nr_cpus(nr: u64) {
    NR_CPUS.init(&nr).expect("Failed to init NR_CPUS");
}

pub fn get_nr_cpus() -> u64 {
    *NR_CPUS
}

static AP_FUNC: ImmutAfterInitCell<fn()> = ImmutAfterInitCell::uninit();

#[repr(C, packed)]
struct TdMailBox {
    command: u32,
    apic_id: u32,
    wakeup_vector: u64,
    rsp: u64,
    percpu: u64,
}

unsafe fn wakeup_ap(
    mailbox: *mut TdMailBox,
    apic_id: u32,
    wakeup_vector: u64,
    rsp: u64,
    percpu: u64,
) {
    (*mailbox).apic_id = 0;
    (*mailbox).wakeup_vector = 0;
    (*mailbox).rsp = 0;
    (*mailbox).percpu = 0;
    (*mailbox).command = 0;
    _mm_sfence();
    (*mailbox).wakeup_vector = wakeup_vector;
    (*mailbox).rsp = rsp;
    (*mailbox).percpu = percpu;
    _mm_sfence();
    (*mailbox).apic_id = apic_id;
    _mm_sfence();
    (*mailbox).command = 0x1u32;
}

fn start_cpu_tdp(apic_id: u32, mbx_addr: VirtAddr, boot_stack: VirtAddr) {
    unsafe {
        let start_rip: u64 = (start_ap_tdp as *const u8) as u64;
        let percpu = PerCpu::alloc(apic_id)
            .expect("Failed to allocate AP per-cpu data")
            .as_mut()
            .unwrap();

        percpu.setup().expect("Failed to setup AP per-cpu area");
        wakeup_ap(
            mbx_addr.as_mut_ptr::<TdMailBox>(),
            apic_id,
            start_rip,
            boot_stack.into(),
            VirtAddr::from(percpu as *mut PerCpu).into(),
        );
        loop {
            if percpu.is_online() {
                break;
            }
        }
    }
}

fn start_secondary_cpus_tdp(cpus: &[ACPICPUInfo], mbx_paddr: PhysAddr) {
    let mut count: usize = 0;
    let guard = PerCPUPageMappingGuard::create_4k(mbx_paddr).expect("Failed to create ptguard");
    let mbx_addr = guard.virt_addr();
    // Heap pages are visible to APs spinning in stage2 memory
    let boot_stack = allocate_pages(2).expect("Failed to allocate AP stack pages");
    let boot_stack_top = boot_stack + (4 * PAGE_SIZE);

    for c in cpus.iter().filter(|c| c.apic_id != 0 && c.enabled) {
        log::info!("Launching AP with APIC-ID {}", c.apic_id);
        start_cpu_tdp(c.apic_id, mbx_addr, boot_stack_top);
        count += 1;
    }
    log::info!("Brought {} AP(s) online", count);
    free_page(boot_stack);
}

fn start_cpu_sev(apic_id: u32) {
    unsafe {
        let start_rip: u64 = (start_ap_sev as *const u8) as u64;
        let percpu = PerCpu::alloc(apic_id)
            .expect("Failed to allocate AP per-cpu data")
            .as_mut()
            .unwrap();

        percpu.setup().expect("Failed to setup AP per-cpu area");
        percpu
            .alloc_svsm_vmsa()
            .expect("Failed to allocate AP SVSM VMSA");

        let mut vmsa = percpu.get_svsm_vmsa().unwrap();
        init_svsm_vmsa(vmsa.vmsa());
        percpu.prepare_svsm_vmsa(start_rip);

        let sev_features = vmsa.vmsa().sev_features;
        let vmsa_pa = vmsa.paddr;

        vmsa.vmsa().enable();
        current_ghcb()
            .ap_create(vmsa_pa, apic_id.into(), 0, sev_features)
            .expect("Failed to launch secondary CPU");
        loop {
            if percpu.is_online() {
                break;
            }
        }
    }
}

fn start_secondary_cpus_sev(cpus: &[ACPICPUInfo]) {
    let mut count: usize = 0;
    for c in cpus.iter().filter(|c| c.apic_id != 0 && c.enabled) {
        log::info!("Launching AP with APIC-ID {}", c.apic_id);
        start_cpu_sev(c.apic_id);
        count += 1;
    }
    log::info!("Brought {} AP(s) online", count);
}

pub fn start_secondary_cpus(cpus: &[ACPICPUInfo], mbx_paddr: PhysAddr, ap_func: fn()) {
    AP_FUNC.init(&ap_func).expect("Already initialized ap func");

    match cpu_type() {
        CpuType::Sev => start_secondary_cpus_sev(cpus),
        CpuType::Td => start_secondary_cpus_tdp(cpus, mbx_paddr),
    }
}

#[no_mangle]
unsafe extern "C" fn start_ap_tdp(apic_id: u32, percpu: u64) -> ! {
    gdt().load();
    idt().load();

    cr0_init();
    cr4_init();
    efer_init();

    let percpu = VirtAddr::from(percpu)
        .as_mut_ptr::<PerCpu>()
        .as_mut()
        .unwrap();

    if percpu.get_apic_id() != apic_id {
        panic!(
            "PerCpu{} and APIC-ID {} are mismatched!",
            percpu.get_apic_id(),
            apic_id
        );
    }

    percpu.setup_on_cpu().expect("setup_on_cpu() failed");

    // boot_stack is still accessible in the new page table
    percpu.load();

    let bp = percpu.get_top_of_stack();

    log::info!("AP Runtime stack starts @ {:#018x}", bp);

    // Enable runtime stack and jump to main function
    unsafe {
        asm!("movq  %rax, %rsp
              jmp   ap_main",
              in("rax") bp.bits(),
              options(att_syntax));
    }

    unreachable!("Should never return from start_ap_tdp!");
}

#[no_mangle]
fn start_ap_sev() {
    this_cpu_mut()
        .setup_on_cpu()
        .expect("setup_on_cpu() failed");
    ap_main();
}

#[no_mangle]
extern "C" fn ap_main() {
    // Send a life-sign
    log::info!("AP with APIC-ID {} is online", this_cpu_mut().get_apic_id());

    // Set CPU online so that BSP can proceed
    this_cpu_mut().set_online();

    if is_tdx() {
        ap_request_loop();
    }

    this_cpu_mut()
        .setup_idle_task(ap_request_loop)
        .expect("Failed to allocated idle task for AP");

    schedule_init();
}

#[no_mangle]
pub extern "C" fn ap_request_loop() {
    let ap_func = *AP_FUNC;
    ap_func();
    panic!("Returned from ap_func!");
}
