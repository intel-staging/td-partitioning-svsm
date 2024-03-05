/* SPDX-License-Identifier: MIT OR Apache-2.0 */

/*
 * Copyright (c) 2022-2023 SUSE LLC
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#include "types.h"

/* Use first 640kb of memory for stage2 loader */
#define STAGE2_RANGE_START	0
#define STAGE2_RANGE_PAGES	158

/* Stage2 is loaded at 64kb */
#define STAGE2_START		0x10000

/* Stage1 stack starts at 632kb with size (4kb - 4) */
#define STAGE1_STACK		0x9e000

/* Flag for AP signaling at the bottom of the stage1 stack page */
#define STAGE2_FLAG		(STAGE1_STACK - 0x1000)
#define STAGE2_MAGIC		0xdecafbad

.text
	.section ".startup.text","ax"
	.code32

	.org 0
	.globl startup_32
startup_32:
	cld
	cli

	/* Enable caches */
	movl	%cr0, %eax
	andl	$~((1 << 30) | (1 << 29)), %eax
	mov	%eax, %cr0

	/*
	 * Setup Stack
	 *
	 * Since stage1 stack is only used for getting run-offset,
	 * it should be OK to be shared across all CPUs.
	 *
	 * The stack starts at 632kb to ensure it won't get
	 * clobbered by the stage2 stack.
	 */
	movl	$STAGE1_STACK, %esp

	/* Store run-offset to %ebp */
	call	2f
2:	popl	%ebp
	leal	2b, %eax
	subl	%eax, %ebp

	/* Default to CPU 0 */
	xorl	%edx, %edx

	/* Discover CPU vendor using CPUID (0) */
	xorl	%eax, %eax
	cpuid
	/* "Genu" */
	cmpl	$0x756e6547, %ebx
	jne	.Lload_stage2
	/* "ineI" */
	cmpl	$0x49656e69, %edx
	jne	.Lload_stage2
	/* "ntel" */
	cmpl	$0x6c65746e, %ecx
	jne	.Lload_stage2

	/* Save TD CPU index */
	mov	%esi, %edx
	test	%edx, %edx
	jnz	.Lap_entry

.Lload_stage2:
	leal	stage2_bin(%ebp), %esi
	movl	$STAGE2_START, %edi
	movl	stage2_size(%ebp), %ecx

	/* Make sure stage2 itself doesn't clobber stage1 stack */
	mov	%ecx, %eax
	addl	$STAGE2_START, %eax
	mov	$STAGE1_STACK, %ebx
	subl	$0x1000, %ebx
	cmpl	%ebx, %eax
	jg	.Lpanic

	shrl	$2, %ecx
	rep movsl

	/* Mark it as done */
	movl	$STAGE2_FLAG, %eax
	movl	$STAGE2_MAGIC, (%eax)

	/* Setup BSP stack for stage 2 */
	movl	$STAGE2_START, %esp

	/* Write startup information to BSP stage2 stack */
	xorl 	%eax, %eax
	pushl	%eax

	leal	kernel_fs_bin_end(%ebp), %edi
	pushl	%edi

	leal	kernel_fs_bin(%ebp), %edi
	pushl	%edi

	leal	kernel_elf_end(%ebp), %edi
	pushl	%edi

	leal	kernel_elf(%ebp), %edi
	pushl	%edi

	jmp	.Lbsp_entry

.Lap_entry:
	movl	$STAGE2_FLAG, %eax
.Lap_wait:
	movl	(%eax), %ebx
	cmpl	$STAGE2_MAGIC, %ebx
	jne	.Lap_wait

.Lbsp_entry:
	/* Jump to stage 2 */
	mov	%edx, %esi
	movl	$STAGE2_START, %eax
	jmp	*%eax

.Lpanic:
	ud2
.data

	.align	4
stage2_bin:
	.incbin "stage1/stage2.bin"
	.align 4
stage2_bin_end:

kernel_elf:
	.incbin "stage1/kernel.elf"
	.align 4
kernel_elf_end:

kernel_fs_bin:
	.incbin "stage1/svsm-fs.bin"
kernel_fs_bin_end:

	.align 4
stage2_size:
	.long	stage2_bin_end - stage2_bin
