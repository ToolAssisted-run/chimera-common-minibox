/* asm_aarch64.h - what the aarch64 assembly needs said differently for ELF
 * (Linux), Mach-O (macOS) and COFF (Windows). One directive per macro: Darwin's assembler
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
#elif defined(_WIN32)
/* COFF (Windows on arm64, llvm-mingw): no symbol prefix, no ELF types or
 * sizes, and a DLL exports only what it is told to, so nothing to hide */
#define MB_SYM(x)            x
#define MB_HIDDEN(x)
#define MB_TYPE_FUNCTION(x)
#define MB_SIZE(x)
#define MB_RODATA_SECTION    .section .rdata,"dr"
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

/* FPSR's flags in the 16 bits the context keeps them in (minibox_internal.h,
 * mb_a64_fpsr_pack): bits 0-7 as they are, QC (bit 27) as bit 8. wv: FPSR in,
 * the packed word out; wt: scratch. */
.macro fpsr_pack wv, wt
	ubfx \wt, \wv, #27, #1
	and \wv, \wv, #0xff
	orr \wv, \wv, \wt, lsl #8
.endm

/* and back: xv the packed word in (zero-extended), FPSR's value out; xt:
 * scratch */
.macro fpsr_unpack xv, xt
	ubfx \xt, \xv, #8, #1
	and \xv, \xv, #0xff
	orr \xv, \xv, \xt, lsl #27
.endm

#endif
