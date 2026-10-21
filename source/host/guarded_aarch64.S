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
 *   - "%fs" is the word at MB_TP_SLOT, where an aarch64 guest finds its
 *     thread pointer (minibox_internal.h). Every aarch64 guest owns it
 *     (fs_swap is always on), so what it held is parked at entry and put back
 *     on the way out exactly as guarded.S does for a Rust guest;
 *   - the interop blob keeps no per-host-thread block (no gs): an escape has
 *     the context's four stack fields to put back, and the context word at
 *     MB_INTEROP_SLOT to clear, where guarded.S clears gs:0x18;
 *   - the floating-point control words are FPCR alone, kept in the context's
 *     MXCSR fields (minibox_internal.h, mb_fpu_get);
 *   - the guest's fault handler runs from a trampoline that cannot end by
 *     returning to the faulting instruction (that needs a register): it ends
 *     in a udf, and tripguard.c's SIGILL handler puts every register back.
 *
 * Layout: CTX_* must match mb_context (context.c asserts every one).
 */

#include "asm_aarch64.h"

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
#define CTX_GUEST_MXCSR   0x258   /* FPCR, on aarch64 */
#define CTX_HOST_MXCSR    0x25c

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
#define FRAME_PREV_FPCR     208  /* the context's host FPCR before this call */
#define FRAME_SIZE          224

	.text
	.globl MB_SYM(mb_guarded_call)
	.globl MB_SYM(mb_guarded_escape)
	.globl MB_SYM(mb_guarded_escape_now)
	MB_HIDDEN(mb_guarded_call)
	MB_HIDDEN(mb_guarded_escape)
	MB_HIDDEN(mb_guarded_escape_now)
	MB_TYPE_FUNCTION(MB_SYM(mb_guarded_call))
	MB_TYPE_FUNCTION(MB_SYM(mb_guarded_escape))
	MB_TYPE_FUNCTION(MB_SYM(mb_guarded_escape_now))

/* Entered by a guest-entry thunk (a branch, not a call: x30 is still the
 * caller's return address) with x9 = the context and x10 = the guest
 * function, the guest's arguments untouched in x0-x7. */
	.p2align 4
MB_SYM(mb_guarded_call):
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
	/* the floating-point control register: the host's parked in the context
	 * (the outer call's kept in the record), the guest's loaded. Before the
	 * dead check, so the landing is the same for every way of arriving. */
	ldr w11, [x9, #CTX_HOST_MXCSR]
	str w11, [sp, #FRAME_PREV_FPCR]
	mrs x11, fpcr
	str w11, [x9, #CTX_HOST_MXCSR]
	ldr w11, [x9, #CTX_GUEST_MXCSR]
	msr fpcr, x11

	/* what the slot held, where the syscall dispatcher and the way out both
	 * read it */
	tp_slot_addr x12
	ldr x11, [x12]
	str x11, [x9, #CTX_HOST_FS]
	/* a dead machine runs nothing */
	ldrb w11, [x9, #CTX_DEAD]
	cbnz w11, .Lrefused

	/* the guest's thread pointer, once it has one */
	ldrb w11, [x9, #CTX_FS_SWAP]
	cbz w11, 2f
	ldr x11, [x9, #CTX_THREAD_AREA]
	cbz x11, 2f
	str x11, [x12]
2:
	/* The callee-saved registers reach the guest holding nothing: they hold
	 * the host's values here, and a guest prologue or a cothread switch
	 * writes them into memory a state carries (guarded.S; x29 is the blob's,
	 * d8-d15 too). The host's are in the record above. */
	mov x19, xzr
	mov x20, xzr
	mov x21, xzr
	mov x22, xzr
	mov x23, xzr
	mov x24, xzr
	mov x25, xzr
	mov x26, xzr
	mov x27, xzr
	mov x28, xzr
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
	/* and what the slot held back */
	ldr x10, [x9, #CTX_HOST_FS]
	tp_slot_addr x11
	str x10, [x11]
	/* the guest's FPCR kept, the host's back, and the outer call's host
	 * FPCR back in the context */
	mrs x10, fpcr
	str w10, [x9, #CTX_GUEST_MXCSR]
	ldr w10, [x9, #CTX_HOST_MXCSR]
	msr fpcr, x10
	ldr w10, [sp, #FRAME_PREV_FPCR]
	str w10, [x9, #CTX_HOST_MXCSR]
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
	MB_SIZE(MB_SYM(mb_guarded_call))

/* From host C (x0 = the context): leave for the innermost record now.
 * Everything on the host stack below that record is abandoned. */
	.p2align 4
MB_SYM(mb_guarded_escape_now):
	ldr x1, [x0, #CTX_ESC_RSP]
	mov sp, x1

/* From a fault handler, which has pointed the interrupted context's sp at the
 * record and its pc here. Undoes what the blob's entry did to the context,
 * then leaves the way a return would, with 0. */
MB_SYM(mb_guarded_escape):
	ldr x9, [sp, #FRAME_CTX]
	ldr x10, [sp, #FRAME_HOST_RSP]
	str x10, [x9, #CTX_HOST_RSP]
	ldr x10, [sp, #FRAME_GUEST_RSP]
	str x10, [x9, #CTX_GUEST_RSP]
	ldr x10, [sp, #FRAME_HOST_RSP_ALT]
	str x10, [x9, #CTX_HOST_RSP_ALT]
	ldr x10, [sp, #FRAME_GUEST_RSP_ALT]
	str x10, [x9, #CTX_GUEST_RSP_ALT]
	/* the thread is in no guest call: the blob's context word, as gs:0x18 */
	interop_slot_addr x10
	str xzr, [x10]
	mov x0, #0
	b .Llanding
	MB_SIZE(MB_SYM(mb_guarded_escape))

#if defined(__linux__)
/* Linux: the guest's fault handler, run on the faulting thread's own stack
 * (guarded.S says why). The signal handler (tripguard.c, send_to_guest) points
 * the interrupted thread here with sp 128 bytes below its own, rounded down to
 * 16, x0 and x1 the handler's arguments, x2 the handler and x3 this thread's
 * record of the interrupted registers: x0-x30, sp, pc and pstate.
 *
 * aarch64 cannot jump back to the faulting pc without a register to hold it,
 * and every register is the faulting code's. So the vector state is saved and
 * put back here, and the general registers, the flags, sp and pc by the
 * SIGILL handler the udf at the end raises (tripguard.c, fault_tramp_resume),
 * from the copy of the record on this stack: the record itself is the next
 * fault's. The handler's answer is in x0 at the udf; 0 marks the address
 * declined, and the retry is an unhandled fault.
 *
 * Two copies of one body, as guarded.S has: the guest's (a fault in guest
 * code; counts as guest code to the fault handler) and the host's (a fault in
 * host code; the handler is the guest-entry thunk). */
#define TRAMP_REC           0     /* x0-x30, sp, pc, pstate: 34 words */
#define TRAMP_FPSR          272   /* then FPCR */
#define TRAMP_ADDR          288   /* the handler's first argument, the address */
#define TRAMP_V             304   /* q0-q31 */
#define TRAMP_SIZE          816
	.macro FAULT_TRAMP name
	.globl MB_SYM(\name)
	MB_HIDDEN(\name)
	MB_TYPE_FUNCTION(MB_SYM(\name))
	.p2align 4
MB_SYM(\name):
	sub sp, sp, #TRAMP_SIZE
	.irp n, 0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32
	ldp x4, x5, [x3, #\n * 8]
	stp x4, x5, [sp, #TRAMP_REC + \n * 8]
	.endr
	stp q0, q1, [sp, #TRAMP_V + 0]
	stp q2, q3, [sp, #TRAMP_V + 32]
	stp q4, q5, [sp, #TRAMP_V + 64]
	stp q6, q7, [sp, #TRAMP_V + 96]
	stp q8, q9, [sp, #TRAMP_V + 128]
	stp q10, q11, [sp, #TRAMP_V + 160]
	stp q12, q13, [sp, #TRAMP_V + 192]
	stp q14, q15, [sp, #TRAMP_V + 224]
	stp q16, q17, [sp, #TRAMP_V + 256]
	stp q18, q19, [sp, #TRAMP_V + 288]
	stp q20, q21, [sp, #TRAMP_V + 320]
	stp q22, q23, [sp, #TRAMP_V + 352]
	stp q24, q25, [sp, #TRAMP_V + 384]
	stp q26, q27, [sp, #TRAMP_V + 416]
	stp q28, q29, [sp, #TRAMP_V + 448]
	stp q30, q31, [sp, #TRAMP_V + 480]
	mrs x4, fpsr
	mrs x5, fpcr
	stp x4, x5, [sp, #TRAMP_FPSR]
	str x0, [sp, #TRAMP_ADDR]
	blr x2
	ldp x4, x5, [sp, #TRAMP_FPSR]
	msr fpsr, x4
	msr fpcr, x5
	ldp q0, q1, [sp, #TRAMP_V + 0]
	ldp q2, q3, [sp, #TRAMP_V + 32]
	ldp q4, q5, [sp, #TRAMP_V + 64]
	ldp q6, q7, [sp, #TRAMP_V + 96]
	ldp q8, q9, [sp, #TRAMP_V + 128]
	ldp q10, q11, [sp, #TRAMP_V + 160]
	ldp q12, q13, [sp, #TRAMP_V + 192]
	ldp q14, q15, [sp, #TRAMP_V + 224]
	ldp q16, q17, [sp, #TRAMP_V + 256]
	ldp q18, q19, [sp, #TRAMP_V + 288]
	ldp q20, q21, [sp, #TRAMP_V + 320]
	ldp q22, q23, [sp, #TRAMP_V + 352]
	ldp q24, q25, [sp, #TRAMP_V + 384]
	ldp q26, q27, [sp, #TRAMP_V + 416]
	ldp q28, q29, [sp, #TRAMP_V + 448]
	ldp q30, q31, [sp, #TRAMP_V + 480]
	.globl MB_SYM(\name\()_resume)
	MB_HIDDEN(\name\()_resume)
MB_SYM(\name\()_resume):
	udf #0xfa17               /* sp: the copy; x0: the handler's answer */
	.globl MB_SYM(\name\()_end)
	MB_HIDDEN(\name\()_end)
MB_SYM(\name\()_end):
	MB_SIZE(MB_SYM(\name))
	.endm

	FAULT_TRAMP mb_fault_tramp_guest
	FAULT_TRAMP mb_fault_tramp_host
#endif

	MB_NOTE_GNU_STACK
