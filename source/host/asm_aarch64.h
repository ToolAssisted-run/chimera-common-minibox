/* asm_aarch64.h - what the aarch64 assembly needs said differently for ELF
 * (Linux) and Mach-O (macOS). One directive per macro: Darwin's assembler
 * reads ';' as a comment, so nothing here may join two statements. */
#ifndef MB_ASM_AARCH64_H
#define MB_ASM_AARCH64_H

#if defined(__APPLE__)
#define MB_SYM(x)            _##x
#define MB_HIDDEN(x)         .private_extern _##x
#define MB_TYPE_FUNCTION(x)
#define MB_SIZE(x)
#define MB_RODATA_SECTION    .section __TEXT,__const
#define MB_NOTE_GNU_STACK
#else
#define MB_SYM(x)            x
#define MB_HIDDEN(x)         .hidden x
#define MB_TYPE_FUNCTION(x)  .type x, %function
#define MB_SIZE(x)           .size x, . - x
#define MB_RODATA_SECTION    .section .rodata.mb_interop, "a"
#define MB_NOTE_GNU_STACK    .section .note.GNU-stack,"",%progbits
#endif

/* x = MB_INTEROP_SLOT (0x35f00010000): the context of the guest call this
 * thread is in, 0 while it runs host code (interop_aarch64.S) */
.macro interop_slot_addr x
	movz \x, #0x0001, lsl #16
	movk \x, #0x035f, lsl #32
.endm

/* x = MB_TP_SLOT (0x36ef0000000): the guest's thread pointer, a word of
 * memory on aarch64 (minibox_internal.h) */
.macro tp_slot_addr x
	movz \x, #0xf000, lsl #16
	movk \x, #0x036e, lsl #32
.endm

#endif
