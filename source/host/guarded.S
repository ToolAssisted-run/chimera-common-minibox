/* guarded.S - every call into the guest goes through here, so that a guest
 * that dies can hand control back instead of taking the process with it.
 *
 * A guest dies in ways that are no fault of the host: it calls abort(), it
 * finds its own heap corrupt and halts, it follows a wild pointer, it exits.
 * Each of those used to end in a trap, and the trap ended the frontend - the
 * session, whatever was not saved, and any chance of saying what happened.
 *
 * So each exported call is entered with an ESCAPE RECORD on the host stack: the
 * caller's callee-saved registers, the interop fields the blob is about to
 * change, and where the previous record was. A guest that dies is marked dead
 * (mb_host_guest_death) and control is sent to mb_guarded_escape with the stack
 * pointer at that record - from host C through mb_guarded_escape_now, or from
 * a fault handler by rewriting the interrupted context - and the call returns
 * 0 to its caller as if the guest had. Nothing of the guest runs after that:
 * a call into a dead machine returns 0 at once, until a state load revives it.
 *
 * The interop blob's own exit path is what the escape undoes by hand: the
 * stack bounds it saved in the TEB (Windows) or the per-thread block (Linux),
 * the context pointer at gs:0x18, and the four stack fields of the context -
 * put back to what they were before this call, which also covers a call made
 * from inside a host callback (the blob's "alt" stacks).
 *
 * Layout: CTX_* must match mb_context (context.c asserts every one), and the
 * escape record is the frame below.
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

#define CALL_GUEST_IMPL   0x35f00000200

/* the escape record, at the stack pointer the blob is called with */
#define FRAME_CTX           0
#define FRAME_PREV_ESC      8
#define FRAME_HOST_RSP      16
#define FRAME_GUEST_RSP     24
#define FRAME_HOST_RSP_ALT  32
#define FRAME_GUEST_RSP_ALT 40
#define FRAME_XMM           48   /* xmm6..xmm15, ten of them */
#define FRAME_SIZE          216  /* 8 pushes before it: rsp % 16 == 0 at the call */

#ifdef _WIN32
#define SEH(...) __VA_ARGS__
#else
#define SEH(...)
#endif

	.text
	.globl mb_guarded_call
	.globl mb_guarded_escape
	.globl mb_guarded_escape_now
#ifdef __ELF__
	.hidden mb_guarded_call
	.hidden mb_guarded_escape
	.hidden mb_guarded_escape_now
	.type mb_guarded_call, @function
	.type mb_guarded_escape, @function
	.type mb_guarded_escape_now, @function
#endif

/* Entered by a guest-entry thunk with r10 = the context and r11 = the guest
 * function, the guest's arguments untouched in the sysv registers, and the
 * return address on the stack. The registers saved are every one some caller
 * expects kept - sysv's, and win64's rdi, rsi and xmm6-15 as well, because on
 * Windows the thunk's caller is a win64-to-sysv adapter and an escape skips
 * whatever the guest did to them. */
	.p2align 4
mb_guarded_call:
	SEH(.seh_proc mb_guarded_call)
	pushq %rbx
	SEH(.seh_pushreg %rbx)
	pushq %rbp
	SEH(.seh_pushreg %rbp)
	pushq %r12
	SEH(.seh_pushreg %r12)
	pushq %r13
	SEH(.seh_pushreg %r13)
	pushq %r14
	SEH(.seh_pushreg %r14)
	pushq %r15
	SEH(.seh_pushreg %r15)
	pushq %rdi
	SEH(.seh_pushreg %rdi)
	pushq %rsi
	SEH(.seh_pushreg %rsi)
	subq $FRAME_SIZE, %rsp
	SEH(.seh_stackalloc FRAME_SIZE)
	movdqu %xmm6, FRAME_XMM+0(%rsp)
	SEH(.seh_savexmm %xmm6, FRAME_XMM+0)
	movdqu %xmm7, FRAME_XMM+16(%rsp)
	SEH(.seh_savexmm %xmm7, FRAME_XMM+16)
	movdqu %xmm8, FRAME_XMM+32(%rsp)
	SEH(.seh_savexmm %xmm8, FRAME_XMM+32)
	movdqu %xmm9, FRAME_XMM+48(%rsp)
	SEH(.seh_savexmm %xmm9, FRAME_XMM+48)
	movdqu %xmm10, FRAME_XMM+64(%rsp)
	SEH(.seh_savexmm %xmm10, FRAME_XMM+64)
	movdqu %xmm11, FRAME_XMM+80(%rsp)
	SEH(.seh_savexmm %xmm11, FRAME_XMM+80)
	movdqu %xmm12, FRAME_XMM+96(%rsp)
	SEH(.seh_savexmm %xmm12, FRAME_XMM+96)
	movdqu %xmm13, FRAME_XMM+112(%rsp)
	SEH(.seh_savexmm %xmm13, FRAME_XMM+112)
	movdqu %xmm14, FRAME_XMM+128(%rsp)
	SEH(.seh_savexmm %xmm14, FRAME_XMM+128)
	movdqu %xmm15, FRAME_XMM+144(%rsp)
	SEH(.seh_savexmm %xmm15, FRAME_XMM+144)
	SEH(.seh_endprologue)

	/* the record: who, the record before this one, and the context's stack
	 * fields as the blob is about to find them */
	movq %r10, FRAME_CTX(%rsp)
	movq CTX_ESC_RSP(%r10), %rax
	movq %rax, FRAME_PREV_ESC(%rsp)
	movq CTX_HOST_RSP(%r10), %rax
	movq %rax, FRAME_HOST_RSP(%rsp)
	movq CTX_GUEST_RSP(%r10), %rax
	movq %rax, FRAME_GUEST_RSP(%rsp)
	movq CTX_HOST_RSP_ALT(%r10), %rax
	movq %rax, FRAME_HOST_RSP_ALT(%rsp)
	movq CTX_GUEST_RSP_ALT(%r10), %rax
	movq %rax, FRAME_GUEST_RSP_ALT(%rsp)
	movq %rsp, CTX_ESC_RSP(%r10)
	incq CTX_CALLS(%r10)

	/* the host's %fs, where the syscall dispatcher and the way out both read it */
	cmpb $0, CTX_FS_SWAP(%r10)
	je 1f
	rdfsbase %rax
	movq %rax, CTX_HOST_FS(%r10)
1:
	/* a dead machine runs nothing */
	cmpb $0, CTX_DEAD(%r10)
	jne .Lrefused

	/* the guest's %fs, once it has one (a Rust guest uses %fs-direct TLS) */
	cmpb $0, CTX_FS_SWAP(%r10)
	je 2f
	movq CTX_THREAD_AREA(%r10), %rax
	testq %rax, %rax
	jz 2f
	wrfsbase %rax
2:
	movabsq $CALL_GUEST_IMPL, %rax
	callq *%rax

	/* rax: what the guest returned, or 0 from a refusal or an escape.
	 * rsp: the record, whichever way control arrived. */
.Llanding:
	movq FRAME_CTX(%rsp), %r10
	movq FRAME_PREV_ESC(%rsp), %r11
	movq %r11, CTX_ESC_RSP(%r10)
	cmpb $0, CTX_FS_SWAP(%r10)
	je 3f
	movq %rax, %r11
	movq CTX_HOST_FS(%r10), %rax
	wrfsbase %rax
	movq %r11, %rax
3:
	movdqu FRAME_XMM+0(%rsp), %xmm6
	movdqu FRAME_XMM+16(%rsp), %xmm7
	movdqu FRAME_XMM+32(%rsp), %xmm8
	movdqu FRAME_XMM+48(%rsp), %xmm9
	movdqu FRAME_XMM+64(%rsp), %xmm10
	movdqu FRAME_XMM+80(%rsp), %xmm11
	movdqu FRAME_XMM+96(%rsp), %xmm12
	movdqu FRAME_XMM+112(%rsp), %xmm13
	movdqu FRAME_XMM+128(%rsp), %xmm14
	movdqu FRAME_XMM+144(%rsp), %xmm15
	addq $FRAME_SIZE, %rsp
	popq %rsi
	popq %rdi
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbp
	popq %rbx
	ret

.Lrefused:
	xorl %eax, %eax
	jmp .Llanding
	SEH(.seh_endproc)

/* From host C (sysv: the context in rdi): leave for the innermost record now.
 * Everything on the host stack below that record is abandoned. */
	.p2align 4
mb_guarded_escape_now:
	movq CTX_ESC_RSP(%rdi), %rsp

/* From a fault handler, which has pointed the interrupted context's rsp at the
 * record and its rip here. Undoes what the blob's entry did, then leaves the
 * way a return would, with 0. */
mb_guarded_escape:
	movq FRAME_CTX(%rsp), %r10
	/* the stack bounds the blob pushed on its way in, just below the return
	 * address the call left: gs:0x8 first, then gs:0x10 */
	movq -16(%rsp), %rax
	movq %rax, %gs:0x8
	movq -24(%rsp), %rax
	movq %rax, %gs:0x10
	xorl %eax, %eax
	movq %rax, %gs:0x18
	movq FRAME_HOST_RSP(%rsp), %rax
	movq %rax, CTX_HOST_RSP(%r10)
	movq FRAME_GUEST_RSP(%rsp), %rax
	movq %rax, CTX_GUEST_RSP(%r10)
	movq FRAME_HOST_RSP_ALT(%rsp), %rax
	movq %rax, CTX_HOST_RSP_ALT(%r10)
	movq FRAME_GUEST_RSP_ALT(%rsp), %rax
	movq %rax, CTX_GUEST_RSP_ALT(%r10)
	xorl %eax, %eax
	jmp .Llanding

#ifdef __ELF__
	.section .note.GNU-stack,"",@progbits
#endif
