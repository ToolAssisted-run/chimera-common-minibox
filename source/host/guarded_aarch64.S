/* guarded_aarch64.S - guarded.S for an aarch64 host: every call into the guest
 * goes through here, so that a guest that dies can hand control back instead
 * of taking the process with it. Read guarded.S first; this is the same
 * routine, register for register where aarch64 allows, and the comments there
 * are the ones that matter.
 *
 * Differences from x86-64:
 *   - the entry thunk passes the context in x9 and the guest function in x10
 *     (r10/r11 there), the arguments untouched in x0-x7;
 *   - the escape record saves x19-x28, the frame pointer and the link
 *     register, and d8-d15: what AAPCS64 says a callee keeps;
 *   - "%fs" is TPIDR_EL0, which glibc and the guest's musl both live on. Every
 *     aarch64 guest owns it (fs_swap is always on), so the host's is parked at
 *     entry and put back on the way out exactly as guarded.S does for a Rust
 *     guest;
 *   - the interop blob keeps no per-host-thread block (no gs), so an escape
 *     has only the context's four stack fields to put back.
 *
 * Layout: CTX_* must match mb_context (context.c asserts every one).
 */

#define CTX_THREAD_AREA   0x000
#define CTX_HOST_RSP      0x008
#define CTX_GUEST_RSP     0x010
#define CTX_HOST_RSP_ALT  0x018
#define CTX_GUEST_RSP_ALT 0x020
#define CTX_HOST_FS       0x238
#define CTX_FS_SWAP       0x240
#define CTX_DEAD          0x241
#define CTX_ESC_RSP       0x248
#define CTX_CALLS         0x250

/* the escape record, at the stack pointer the blob is called with */
#define FRAME_CTX           0
#define FRAME_PREV_ESC      8
#define FRAME_HOST_RSP      16
#define FRAME_GUEST_RSP     24
#define FRAME_HOST_RSP_ALT  32
#define FRAME_GUEST_RSP_ALT 40
#define FRAME_X19           48   /* x19..x28, then x29 and x30 */
#define FRAME_X29           128
#define FRAME_D8            144  /* d8..d15 */
#define FRAME_SIZE          208

	.text
	.globl mb_guarded_call
	.globl mb_guarded_escape
	.globl mb_guarded_escape_now
	.hidden mb_guarded_call
	.hidden mb_guarded_escape
	.hidden mb_guarded_escape_now
	.type mb_guarded_call, %function
	.type mb_guarded_escape, %function
	.type mb_guarded_escape_now, %function

/* Entered by a guest-entry thunk (a branch, not a call: x30 is still the
 * caller's return address) with x9 = the context and x10 = the guest
 * function, the guest's arguments untouched in x0-x7. */
	.p2align 4
mb_guarded_call:
	sub sp, sp, #FRAME_SIZE
	stp x19, x20, [sp, #FRAME_X19 + 0]
	stp x21, x22, [sp, #FRAME_X19 + 16]
	stp x23, x24, [sp, #FRAME_X19 + 32]
	stp x25, x26, [sp, #FRAME_X19 + 48]
	stp x27, x28, [sp, #FRAME_X19 + 64]
	stp x29, x30, [sp, #FRAME_X29]
	stp d8, d9, [sp, #FRAME_D8 + 0]
	stp d10, d11, [sp, #FRAME_D8 + 16]
	stp d12, d13, [sp, #FRAME_D8 + 32]
	stp d14, d15, [sp, #FRAME_D8 + 48]
	add x29, sp, #FRAME_X29

	/* the record: who, the record before this one, and the context's stack
	 * fields as the blob is about to find them */
	str x9, [sp, #FRAME_CTX]
	ldr x11, [x9, #CTX_ESC_RSP]
	str x11, [sp, #FRAME_PREV_ESC]
	ldr x11, [x9, #CTX_HOST_RSP]
	str x11, [sp, #FRAME_HOST_RSP]
	ldr x11, [x9, #CTX_GUEST_RSP]
	str x11, [sp, #FRAME_GUEST_RSP]
	ldr x11, [x9, #CTX_HOST_RSP_ALT]
	str x11, [sp, #FRAME_HOST_RSP_ALT]
	ldr x11, [x9, #CTX_GUEST_RSP_ALT]
	str x11, [sp, #FRAME_GUEST_RSP_ALT]
	mov x11, sp
	str x11, [x9, #CTX_ESC_RSP]
	ldr x11, [x9, #CTX_CALLS]
	add x11, x11, #1
	str x11, [x9, #CTX_CALLS]

	/* the host's thread pointer, where the syscall dispatcher and the way
	 * out both read it */
	adrp x11, :got:mb_fs_swap
	ldr x11, [x11, #:got_lo12:mb_fs_swap]
	ldrb w11, [x11]
	cbz w11, 1f
	mrs x11, tpidr_el0
	str x11, [x9, #CTX_HOST_FS]
1:
	/* a dead machine runs nothing */
	ldrb w11, [x9, #CTX_DEAD]
	cbnz w11, .Lrefused

	/* the guest's thread pointer, once it has one */
	ldrb w11, [x9, #CTX_FS_SWAP]
	cbz w11, 2f
	ldr x11, [x9, #CTX_THREAD_AREA]
	cbz x11, 2f
	msr tpidr_el0, x11
2:
	/* call_guest_impl, at its fixed address: 0x35f00000200 */
	movz x11, #0x0200
	movk x11, #0x035f, lsl #32
	blr x11

	/* x0: what the guest returned, or 0 from a refusal or an escape.
	 * sp: the record, whichever way control arrived. */
.Llanding:
	ldr x9, [sp, #FRAME_CTX]
	ldr x10, [sp, #FRAME_PREV_ESC]
	str x10, [x9, #CTX_ESC_RSP]
	/* the host's thread pointer back, whenever entry parked it */
	adrp x10, :got:mb_fs_swap
	ldr x10, [x10, #:got_lo12:mb_fs_swap]
	ldrb w10, [x10]
	cbz w10, 3f
	ldr x10, [x9, #CTX_HOST_FS]
	msr tpidr_el0, x10
3:
	ldp d8, d9, [sp, #FRAME_D8 + 0]
	ldp d10, d11, [sp, #FRAME_D8 + 16]
	ldp d12, d13, [sp, #FRAME_D8 + 32]
	ldp d14, d15, [sp, #FRAME_D8 + 48]
	ldp x19, x20, [sp, #FRAME_X19 + 0]
	ldp x21, x22, [sp, #FRAME_X19 + 16]
	ldp x23, x24, [sp, #FRAME_X19 + 32]
	ldp x25, x26, [sp, #FRAME_X19 + 48]
	ldp x27, x28, [sp, #FRAME_X19 + 64]
	ldp x29, x30, [sp, #FRAME_X29]
	add sp, sp, #FRAME_SIZE
	ret

.Lrefused:
	mov x0, #0
	b .Llanding
	.size mb_guarded_call, . - mb_guarded_call

/* From host C (x0 = the context): leave for the innermost record now.
 * Everything on the host stack below that record is abandoned. */
	.p2align 4
mb_guarded_escape_now:
	ldr x1, [x0, #CTX_ESC_RSP]
	mov sp, x1

/* From a fault handler, which has pointed the interrupted context's sp at the
 * record and its pc here. Undoes what the blob's entry did to the context,
 * then leaves the way a return would, with 0. */
mb_guarded_escape:
	ldr x9, [sp, #FRAME_CTX]
	ldr x10, [sp, #FRAME_HOST_RSP]
	str x10, [x9, #CTX_HOST_RSP]
	ldr x10, [sp, #FRAME_GUEST_RSP]
	str x10, [x9, #CTX_GUEST_RSP]
	ldr x10, [sp, #FRAME_HOST_RSP_ALT]
	str x10, [x9, #CTX_HOST_RSP_ALT]
	ldr x10, [sp, #FRAME_GUEST_RSP_ALT]
	str x10, [x9, #CTX_GUEST_RSP_ALT]
	mov x0, #0
	b .Llanding
	.size mb_guarded_escape, . - mb_guarded_escape

	.section .note.GNU-stack,"",%progbits
