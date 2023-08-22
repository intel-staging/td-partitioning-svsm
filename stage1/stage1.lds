/* SPDX-License-Identifier: MIT OR Apache-2.0 */

/*
 * Copyright (c) 2022-2023 SUSE LLC
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	.stext = ALIGN(textbase - 65535, 65536);
	. = .stext;
	.text : { *(.startup.*) *(.text) *(.text.*) }

	.sdata = ALIGN(database - 4095, 4096);
	. = .sdata;
	.data : { *(.data) }

	.srodata = ALIGN(rodatabase - 4095, 4096);
	. = .srodata;
	.rodata : { *(.rodata) }

	/*
	 * Subtract an extra byte so that edata and the .init function
	 * symbols don't alias, which would be confusing when
	 * examining the resulting binary.
	 */
	.sbss = ALIGN(bssbase - 4095 - 1, 4096);
	. = .sbss;
	.bss . : { *(.bss) }
	edata = .;

	. = 0xffdffe00;
	.sinit = .;
	.init . : {
		*(.init);
		. = 512 - 32 - 256;
		*(.sevmeta);
		. = 512 - 16;
		*(.resetvector);
		. = 512;
	}
	einit = .;

	textbase = .sdata - SIZEOF(.text);
	database = .srodata - SIZEOF(.data);
	rodatabase = .sbss - SIZEOF(.rodata);
	bssbase = .sinit - SIZEOF(.bss);

	/DISCARD/ : {*(.*)}
}

ENTRY(startup_32)
