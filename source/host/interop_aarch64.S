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
 * word at MB_INTEROP_SLOT (MB_ORG + 0x10000, its own page, read-write),
 * written on every entry. One machine is entered at a time - the block's
 * address is fixed - so one word per process is all there is to know.
 *
 * What the blob does NOT do is touch TPIDR_EL0: as on x86-64, the guest's and
 * the host's thread pointers are swapped by host C (the syscall dispatcher,
 * mb_guarded_call, the extcall wrappers in context.c).
 *
 * Every way back into guest code zeroes the scratch registers but x0, as the
 * x86-64 blob's stubs do: a guest that spills one must not carry a host
 * address into its savestates. The frame pointer and link register are kept
 * on the guest stack across a syscall, which is also the frame a new guest
 * thread starts from (threading.c: {x29 = 0, x30 = entry}).
 *
 * Context offsets: see mb_context and the asserts in context.c.
 */

#define CTX_HOST_RSP      0x008
#define CTX_GUEST_RSP     0x010
#define CTX_HOST_RSP_ALT  0x018
#define CTX_GUEST_RSP_ALT 0x020
#define CTX_DISPATCH      0x028
#define CTX_HOST_PTR      0x030
#define CTX_EXTCALL       0x038

/* x = MB_INTEROP_SLOT (0x35f00010000) */
.macro slot_addr x
	movz \x, #0x0001, lsl #16
	movk \x, #0x035f, lsl #32
.endm

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

	.section .rodata.mb_interop, "a"
	.balign 16
	.globl mb_interop_bin
	.hidden mb_interop_bin
mb_interop_bin:
	.fill 0x80, 1, 0

/* ---- 0x080 guest_syscall ---- */
	.org 0x80
	stp x29, x30, [sp, #-16]!
	slot_addr x16
	ldr x16, [x16]
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
	slot_addr x11
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
	blr x10
	/* back from the guest: x0 is its answer */
	slot_addr x16
	ldr x16, [x16]
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
	slot_addr x16
	ldr x16, [x16]
	mov x17, sp
	str x17, [x16, #CTX_GUEST_RSP]
	ldr x17, [x16, #CTX_HOST_RSP]
	mov sp, x17
	str x16, [sp, #-16]!
	add x17, x16, #CTX_EXTCALL
	ldr x17, [x17, x9, lsl #3]
	blr x17
	ldr x16, [sp], #16
	ldr x17, [x16, #CTX_GUEST_RSP]
	mov sp, x17
	ldp x29, x30, [sp], #16
/* the way back into guest code from the host, for both of the above */
return_zeroed:
	zero_scratch
	ret
mb_interop_end:

	.balign 4
	.globl mb_interop_bin_len
	.hidden mb_interop_bin_len
mb_interop_bin_len:
	.word mb_interop_end - mb_interop_bin

	.section .note.GNU-stack,"",%progbits
