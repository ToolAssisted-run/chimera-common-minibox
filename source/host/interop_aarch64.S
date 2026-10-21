/* interop_aarch64.S - the interop area for an aarch64 machine: what
 * interop_bin.c's blob is for x86-64, at the same fixed offsets from MB_ORG
 * (0x35f00000000), assembled here rather than embedded as bytes. It is DATA in
 * this library - context.c copies it to MB_ORG and maps it executable - so
 * every branch in it is relative and every absolute address is built from
 * immediates.
 *
 *   0x080  guest_syscall      the guest calls it with blr: number in x8,
 *                             arguments in x0-x5 (the kernel's registers)
 *   0x100  call_guest_simple  host C: (entry, context)
 *   0x200  call_guest_impl    the entry thunks' way in: x9 = context,
 *                             x10 = the guest function, args in x0-x7
 *   0x300  extcall thunks     64 slots x 16 bytes, the guest calls them as
 *                             plain functions: they switch to the host stack
 *                             and call context.extcall_slots[slot]
 *
 * The x86-64 blob finds the running context through gs:0x18, a per-host-thread
 * block; aarch64 has no free register for that, so the context lives in one
 * word at MB_INTEROP_SLOT (MB_ORG + 0x10000, its own page, read-write). As
 * gs:0x18 is, it is written on every way into guest code and cleared on every
 * way out (a system call and a callback included), so a fault handler can
 * tell a thread inside a guest call from one in host code (tripguard.c). One
 * machine is entered at a time - the block's address is fixed - so one word
 * per process is all there is to know.
 *
 * A callback runs with the host's floating-point control register, as the
 * x86-64 wrappers (context.c) give it the host's words: the guest's FPCR is
 * kept in the context on the way out and loaded again on the way back.
 *
 * What the blob does NOT do is touch the guest's thread pointer (the word at
 * MB_TP_SLOT): as on x86-64, host C and mb_guarded_call keep it.
 *
 * Every way back into guest code zeroes the scratch registers but x0, as the
 * x86-64 blob's stubs do: a guest that spills one must not carry a host
 * address into its savestates. The vector registers too, as the x86-64 blob
 * clears xmm0-15 (interop_bin.c): a varargs prologue spills q0-q7 whenever a
 * call passes a floating-point argument. AAPCS64 makes a callee keep d8-d15,
 * the low halves of v8-v15, which x86-64's SysV has no counterpart for, so:
 *   - on entering an export every v register reads zero; the host's d8-d15
 *     wait on the host stack and come back when the export returns;
 *   - after a syscall or a callback v0-v7, v16-v31 and the upper halves of
 *     v8-v15 read zero, and d8-d15 are the guest's own (host C kept them).
 * Only the low 128 bits are cleared: a guest built for the aarch64 baseline
 * uses no SVE. The frame pointer and link register are kept
 * on the guest stack across a syscall, which is also the frame a new guest
 * thread starts from (threading.c: {x29 = 0, x30 = entry}).
 *
 * Context offsets: see mb_context and the asserts in context.c.
 */

#include "asm_aarch64.h"

#define CTX_HOST_RSP      0x008
#define CTX_GUEST_RSP     0x010
#define CTX_HOST_RSP_ALT  0x018
#define CTX_GUEST_RSP_ALT 0x020
#define CTX_DISPATCH      0x028
#define CTX_HOST_PTR      0x030
#define CTX_EXTCALL       0x038
#define CTX_GUEST_MXCSR   0x258   /* FPCR, on aarch64 */
#define CTX_HOST_MXCSR    0x25c


/* everything a guest could read back but x0 */
.macro zero_scratch
	mov x1, xzr
	mov x2, xzr
	mov x3, xzr
	mov x4, xzr
	mov x5, xzr
	mov x6, xzr
	mov x7, xzr
	mov x8, xzr
	mov x9, xzr
	mov x10, xzr
	mov x11, xzr
	mov x12, xzr
	mov x13, xzr
	mov x14, xzr
	mov x15, xzr
	mov x16, xzr
	mov x17, xzr
	mov x18, xzr
.endm

/* every vector register a callee may leave changed: all but d8-d15 */
.macro zero_vectors_scratch
	movi v0.2d, #0
	movi v1.2d, #0
	movi v2.2d, #0
	movi v3.2d, #0
	movi v4.2d, #0
	movi v5.2d, #0
	movi v6.2d, #0
	movi v7.2d, #0
	movi v16.2d, #0
	movi v17.2d, #0
	movi v18.2d, #0
	movi v19.2d, #0
	movi v20.2d, #0
	movi v21.2d, #0
	movi v22.2d, #0
	movi v23.2d, #0
	movi v24.2d, #0
	movi v25.2d, #0
	movi v26.2d, #0
	movi v27.2d, #0
	movi v28.2d, #0
	movi v29.2d, #0
	movi v30.2d, #0
	movi v31.2d, #0
	mov v8.d[1], xzr
	mov v9.d[1], xzr
	mov v10.d[1], xzr
	mov v11.d[1], xzr
	mov v12.d[1], xzr
	mov v13.d[1], xzr
	mov v14.d[1], xzr
	mov v15.d[1], xzr
.endm

	MB_RODATA_SECTION
	.balign 16
	.globl MB_SYM(mb_interop_bin)
	MB_HIDDEN(mb_interop_bin)
MB_SYM(mb_interop_bin):
	.fill 0x80, 1, 0

/* ---- 0x080 guest_syscall ---- */
	.org 0x80
	stp x29, x30, [sp, #-16]!
	interop_slot_addr x17
	ldr x16, [x17]
	str xzr, [x17]
	mov x17, sp
	str x17, [x16, #CTX_GUEST_RSP]
	ldr x17, [x16, #CTX_HOST_RSP]
	mov sp, x17
	str x16, [sp, #-16]!
	/* dispatch(a1..a6, nr, host) */
	mov x6, x8
	ldr x7, [x16, #CTX_HOST_PTR]
	ldr x17, [x16, #CTX_DISPATCH]
	blr x17
	ldr x16, [sp], #16
	interop_slot_addr x17
	str x16, [x17]
	/* the guest stack to return to: guest_rsp, which a thread switch in
	 * the dispatcher may have pointed at another thread's */
	ldr x17, [x16, #CTX_GUEST_RSP]
	mov sp, x17
	ldp x29, x30, [sp], #16
	b return_zeroed

/* ---- 0x100 call_guest_simple(entry, context) ---- */
	.org 0x100
	mov x10, x0
	mov x9, x1
	b call_guest_impl

/* ---- 0x200 call_guest_impl ---- */
	.org 0x200
call_guest_impl:
	/* reentry (the host called back in from a syscall or a callback): the
	 * outer call's host stack and guest stack go to the alt fields */
	ldr x11, [x9, #CTX_HOST_RSP]
	cbz x11, 1f
	str x11, [x9, #CTX_HOST_RSP_ALT]
	ldr x11, [x9, #CTX_GUEST_RSP]
	ldr x12, [x9, #CTX_GUEST_RSP_ALT]
	str x12, [x9, #CTX_GUEST_RSP]
	str x11, [x9, #CTX_GUEST_RSP_ALT]
1:
	stp x29, x30, [sp, #-16]!
	stp d8, d9, [sp, #-16]!
	stp d10, d11, [sp, #-16]!
	stp d12, d13, [sp, #-16]!
	stp d14, d15, [sp, #-16]!
	interop_slot_addr x11
	str x9, [x11]
	mov x11, sp
	str x11, [x9, #CTX_HOST_RSP]
	ldr x11, [x9, #CTX_GUEST_RSP]
	mov sp, x11
	/* no host address goes into the guest: every register that is not an
	 * argument (x0-x7) or the target (x10, a guest address) */
	mov x8, xzr
	mov x9, xzr
	mov x11, xzr
	mov x12, xzr
	mov x13, xzr
	mov x14, xzr
	mov x15, xzr
	mov x16, xzr
	mov x17, xzr
	mov x18, xzr
	mov x29, xzr
	bl zero_vectors
	blr x10
	/* back from the guest: x0 is its answer */
	interop_slot_addr x17
	ldr x16, [x17]
	str xzr, [x17]
	mov x17, sp
	str x17, [x16, #CTX_GUEST_RSP]
	ldr x17, [x16, #CTX_HOST_RSP]
	mov sp, x17
	str xzr, [x16, #CTX_HOST_RSP]
	ldr x17, [x16, #CTX_HOST_RSP_ALT]
	cbz x17, 2f
	str x17, [x16, #CTX_HOST_RSP]
	str xzr, [x16, #CTX_HOST_RSP_ALT]
	ldr x17, [x16, #CTX_GUEST_RSP_ALT]
	ldr x15, [x16, #CTX_GUEST_RSP]
	str x17, [x16, #CTX_GUEST_RSP]
	str x15, [x16, #CTX_GUEST_RSP_ALT]
2:
	ldp d14, d15, [sp], #16
	ldp d12, d13, [sp], #16
	ldp d10, d11, [sp], #16
	ldp d8, d9, [sp], #16
	ldp x29, x30, [sp], #16
	ret

/* ---- 0x300 extcall thunks: slot n at 0x300 + n*16 ---- */
	.org 0x300
	.irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63
	.org 0x300 + \n * 16
	mov x9, #\n
	b extcall_common
	.endr

/* ---- 0x700 the extcalls' common path ---- */
	.org 0x700
extcall_common:
	stp x29, x30, [sp, #-16]!
	interop_slot_addr x17
	ldr x16, [x17]
	str xzr, [x17]
	mov x17, sp
	str x17, [x16, #CTX_GUEST_RSP]
	ldr x17, [x16, #CTX_HOST_RSP]
	mov sp, x17
	str x16, [sp, #-16]!
	mrs x17, fpcr
	str w17, [x16, #CTX_GUEST_MXCSR]
	ldr w17, [x16, #CTX_HOST_MXCSR]
	msr fpcr, x17
	add x17, x16, #CTX_EXTCALL
	ldr x17, [x17, x9, lsl #3]
	blr x17
	ldr x16, [sp], #16
	ldr w17, [x16, #CTX_GUEST_MXCSR]
	msr fpcr, x17
	interop_slot_addr x17
	str x16, [x17]
	ldr x17, [x16, #CTX_GUEST_RSP]
	mov sp, x17
	ldp x29, x30, [sp], #16
/* the way back into guest code from the host, for both of the above */
return_zeroed:
	zero_scratch
	zero_vectors_scratch
	ret

/* call_guest_impl's: every v register zeroed, d8-d15 included (it has saved
 * the host's), out of line because 0x200-0x300 has no room for it */
zero_vectors:
	.irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
	movi v\n\().2d, #0
	.endr
	ret
mb_interop_end:

	.balign 4
	.globl MB_SYM(mb_interop_bin_len)
	MB_HIDDEN(mb_interop_bin_len)
MB_SYM(mb_interop_bin_len):
	.long mb_interop_end - MB_SYM(mb_interop_bin)

	MB_NOTE_GNU_STACK
