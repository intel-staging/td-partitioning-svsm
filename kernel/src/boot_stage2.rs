// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use core::arch::global_asm;

/*
 * %esp: Stage1LaunchInfo pointer
 * %esi: CPU index
 */
global_asm!(
    r#"
        .text
        .section ".startup.text","ax"
        .code32

        .org 0
        .globl startup_32
        startup_32:

        /* Save pointer to startup structure in EBP */
        movl %esp, %ebp
        /*
         * Load a GDT. Despite the naming, it contains valid
         * entries for both, "legacy" 32bit and long mode each.
         */
        movl $gdt64_desc, %eax
        lgdt (%eax)

        movw $0x10, %ax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %fs
        movw %ax, %gs
        movw %ax, %ss

        ljmpl $0x8, $.Lon_svsm32_cs

    .Lon_svsm32_cs:
        /* BSP: CPU index == 0 */
        test %esi, %esi
        jnz .Lskip_paging_setup

        /* Clear out the static page table pages. */
        movl $pgtable_end, %ecx
        subl $pgtable, %ecx
        shrl $2, %ecx
        xorl %eax, %eax
        movl $pgtable, %edi
        rep stosl

        /* Determine the C-bit position within PTEs. */
        call get_pte_c_bit
        movl %eax, %edx

        /* Populate the static page table pages with an identity mapping. */
        movl $pgtable, %edi
        leal 0x1007(%edi), %eax
        movl %eax, 0(%edi)
        addl %edx, 4(%edi)

        addl $0x1000, %edi
        leal 0x1007(%edi), %eax
        movl $4, %ecx
        1: movl %eax, 0(%edi)
        addl %edx, 4(%edi)
        addl $0x1000, %eax
        addl $8, %edi
        decl %ecx
        jnz 1b
        andl $0xfffff000, %edi

        addl $0x1000, %edi
        movl $0x00000183, %eax
        movl $2048, %ecx
        1: movl %eax, 0(%edi)
        addl %edx, 4(%edi)
        addl $0x00200000, %eax
        addl $8, %edi
        decl %ecx
        jnz 1b

        /* Signal APs */
        movl $setup_flag, %edi
        movl $1, (%edi)
        jmp 2f

.Lskip_paging_setup:
        movl $setup_flag, %edi
.Lap_wait:
        movl (%edi), %eax
        test %eax, %eax
        jz .Lap_wait

2:
        /* Enable 64bit PTEs, CR4.PAE. */
        movl %cr4, %eax
        bts $5, %eax
        movl %eax, %cr4

        /* Enable long mode, EFER.LME. */
        movl $0xc0000080, %ecx
        rdmsr
        bts $8, %eax
        wrmsr

        /* Load the static page table root. */
        movl $pgtable, %eax
        movl %eax, %cr3

        /* Enable paging, CR0.PG. */
        movl %cr0, %eax
        bts $31, %eax
        movl %eax, %cr0

        ljmpl $0x18, $startup_64

    get_pte_c_bit:
        movl $0x80000000, %eax
        cpuid
        /* Should fail for non-SEV CPUs */
        cmpl $0x8000001f, %eax
        je .Lis_sev
        xorl %eax, %eax
        ret

    .Lis_sev:
        /*
         * Check that the SNP_Active bit in the SEV_STATUS MSR is set.
         */
        movl $0xc0010131, %ecx
        rdmsr

        testl $0x04, %eax
        jz .Lno_sev_snp

        /* Determine the PTE C-bit position from the CPUID page. */

        /* Read the number of entries. */
        mov CPUID_PAGE, %eax
        /* Create a pointer to the first entry. */
        leal CPUID_PAGE + 16, %ecx

    .Lcheck_entry:
        /* Check that there is another entry. */
        test %eax, %eax
        je .Lno_sev_snp

        /* Check the input parameters of the current entry. */
        cmpl $0x8000001f, (%ecx) /* EAX_IN */
        jne .Lwrong_entry
        cmpl $0, 4(%ecx) /* ECX_IN */
        jne .Lwrong_entry
        cmpl $0, 8(%ecx) /* XCR0_IN (lower half) */
        jne .Lwrong_entry
        cmpl $0, 12(%ecx) /* XCR0_IN (upper half) */
        jne .Lwrong_entry
        cmpl $0, 16(%ecx) /* XSS_IN (lower half) */
        jne .Lwrong_entry
        cmpl $0, 20(%ecx) /* XSS_IN (upper half) */
        jne .Lwrong_entry

        /* All parameters were correct. */
        jmp .Lfound_entry

    .Lwrong_entry:
        /*
         * The current entry doesn't contain the correct input
         * parameters. Try the next one.
         */
        decl %eax
        addl $0x30, %ecx
        jmp .Lcheck_entry

    .Lfound_entry:
        /* Extract the c-bit location from the cpuid entry. */
        movl 28(%ecx), %ebx
        andl $0x3f, %ebx

        /*
         * Verify that the C-bit position is within reasonable bounds:
         * >= 32 and < 64.
         */
        cmpl $32, %ebx
        jl .Lno_sev_snp
        cmpl $64, %ebx
        jae .Lno_sev_snp

        subl $32, %ebx
        xorl %eax, %eax
        btsl %ebx, %eax
        ret

    .Lno_sev_snp:
        hlt
        jmp .Lno_sev_snp

        .code64

    startup_64:
        /* Reload the data segments with 64bit descriptors. */
        movw $0x20, %ax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %fs
        movw %ax, %gs
        movw %ax, %ss

        test %esi, %esi
        jz .Lbsp_main

        /* Fixed mailbox address (under 4G) */
        movq $MAILBOX_PAGE, %rdi

    .Lcheck_command:
        /* Command */
        movl (%edi), %eax
        test %eax, %eax
        jz .Lcheck_command

        /* APIC ID */
        movl 4(%edi), %eax
        cmp %esi, %eax
        jne .Lcheck_command

        /* Wakeup vector */
        movq 8(%edi), %rax

        /* Stack pointer */
        movq 16(%edi), %rbx

        /* PerCpu address */
        movq 24(%edi), %rcx

        /* MB */
        mfence

        /* Ack */
        movl $0, (%edi)

        /*
         * Input argument: apic_id: u32
         *
         * The upper 32 bits of %rdi are all 0s due to MAILBOX_PAGE
         * being under 4G.
         */
        movl %esi, %edi

        /*
         * Input argument: percpu: u64
         */
        movq %rcx, %rsi

        /* Set up stack */
        movq %rbx, %rsp
        jmp *%rax

    .Lbsp_main:
        /* Clear out .bss and transfer control to the main stage2 code. */
        xorq %rax, %rax
        leaq _bss(%rip), %rdi
        leaq _ebss(%rip), %rcx
        subq %rdi, %rcx
        shrq $3, %rcx
        rep stosq

        xorq %rdi, %rdi
        movl %ebp, %edi
        /*
         * As per x86-64 ABI spec, ensure stack is 16 byte aligned before
         * jumping to stage2_main. Below change ensures (%rsp + 8) is a
         * multiple of 16 once the control has been transfered to the
         * entry point function.
         */
        andq $-8, %rsp
        jmp stage2_main

        .data

        .align 4
    setup_flag:
        .long 0

    idt32:
        .rept 32
        .quad 0
        .endr
    idt32_end:

    idt32_desc:
        .word idt32_end - idt32 - 1
        .long idt32

    idt64:
        .rept 32
        .octa 0
        .endr
    idt64_end:

    idt64_desc:
        .word idt64_end - idt64 - 1
        .quad idt64

        .align 256
    gdt64:
        .quad 0
        .quad 0x00cf9a000000ffff /* 32 bit code segment */
        .quad 0x00cf93000000ffff /* 32 bit data segment */
        .quad 0x00af9a000000ffff /* 64 bit code segment */
        .quad 0x00cf92000000ffff /* 64 bit data segment */
    gdt64_end:

    gdt64_desc:
        .word gdt64_end - gdt64 - 1
        .quad gdt64

        .align 4096
        .globl MAILBOX_PAGE
    MAILBOX_PAGE:
        .fill 4096, 1, 0

        .align 4096
        .globl pgtable
    pgtable:
        .fill 7 * 4096, 1, 0
    pgtable_end:"#,
    options(att_syntax)
);
