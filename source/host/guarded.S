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

#ifdef __APPLE__
/* Mach-O: C symbols carry a leading underscore, and there is no .hidden/.type */
#define mb_guarded_call _mb_guarded_call
#define mb_guarded_escape _mb_guarded_escape
#define mb_guarded_escape_now _mb_guarded_escape_now
#define mb_fs_swap _mb_fs_swap
#define mb_xsave_size _mb_xsave_size
#define mb_xsave_mask _mb_xsave_mask
#define mb_fault_tramp_guest _mb_fault_tramp_guest
#define mb_fault_tramp_host _mb_fault_tramp_host
#define mb_gs_to_guest _mb_gs_to_guest
#define mb_gs_to_host _mb_gs_to_host
#define mb_gs_block_c _mb_gs_block_c
#endif

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
#define CTX_GUEST_MXCSR   0x258
#define CTX_HOST_MXCSR    0x25c
#define CTX_GUEST_FCW     0x260
#define CTX_HOST_FCW      0x262

#define CALL_GUEST_IMPL   0x35f00000200

/* the escape record, at the stack pointer the blob is called with */
#define FRAME_CTX           0
#define FRAME_PREV_ESC      8
#define FRAME_HOST_RSP      16
#define FRAME_GUEST_RSP     24
#define FRAME_HOST_RSP_ALT  32
#define FRAME_GUEST_RSP_ALT 40
#define FRAME_XMM           48   /* xmm6..xmm15, ten of them */
#define FRAME_PREV_FCW      208  /* the context's host control words before */
#define FRAME_PREV_MXCSR    212  /* this call: a nested call puts them back */
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
#elif defined(__APPLE__)
	.private_extern mb_guarded_call
	.private_extern mb_guarded_escape
	.private_extern mb_guarded_escape_now
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
	/* the floating-point control words: the host's parked in the context
	 * (the outer call's kept in the record), the guest's loaded. Before the
	 * dead check, so the landing is the same for every way of arriving. */
	movw CTX_HOST_FCW(%r10), %ax
	movw %ax, FRAME_PREV_FCW(%rsp)
	movl CTX_HOST_MXCSR(%r10), %eax
	movl %eax, FRAME_PREV_MXCSR(%rsp)
	fnstcw CTX_HOST_FCW(%r10)
	stmxcsr CTX_HOST_MXCSR(%r10)
	fldcw CTX_GUEST_FCW(%r10)
	ldmxcsr CTX_GUEST_MXCSR(%r10)

	/* the host's %fs, where the syscall dispatcher and the way out both read
	 * it - parked whenever the probe says the instructions exist, not only
	 * for swapping guests: a repair may have installed the guest's thread
	 * pointer meanwhile, and the way out must put the host's back. */
#ifdef __ELF__
	movq mb_fs_swap@GOTPCREL(%rip), %rax
	cmpb $0, (%rax)
#else
	cmpb $0, mb_fs_swap(%rip)
#endif
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
	/* The callee-saved registers reach the guest holding nothing: they hold
	 * the host's values here (pointers into its heap and stacks, different
	 * every run), and a guest prologue or a cothread switch writes them into
	 * memory a state carries, as xmm6-15 were (c0aad51; analysis of
	 * 2026-10-18). The host's are in the record above. */
	xorl %ebx, %ebx
	xorl %ebp, %ebp
	xorl %r12d, %r12d
	xorl %r13d, %r13d
	xorl %r14d, %r14d
	xorl %r15d, %r15d
#ifdef __APPLE__
	/* the guest's gs block for the length of the guest's run (minibox_internal.h);
	 * keeps every register, the arguments among them */
	callq mb_gs_to_guest
#endif
	movabsq $CALL_GUEST_IMPL, %rax
	callq *%rax

	/* rax: what the guest returned, or 0 from a refusal or an escape.
	 * rsp: the record, whichever way control arrived. The direction flag is
	 * cleared first: a guest that escaped between a std and its cld, or
	 * returned with it set, would make the host's memcpy run backwards. */
.Llanding:
	cld
#ifdef __APPLE__
	callq mb_gs_to_host     /* keeps rax: the result */
#endif
	movq FRAME_CTX(%rsp), %r10
	movq FRAME_PREV_ESC(%rsp), %r11
	movq %r11, CTX_ESC_RSP(%r10)
	/* the guest's control words kept, the host's back, and the outer call's
	 * host words back in the context */
	fnstcw CTX_GUEST_FCW(%r10)
	stmxcsr CTX_GUEST_MXCSR(%r10)
	fldcw CTX_HOST_FCW(%r10)
	ldmxcsr CTX_HOST_MXCSR(%r10)
	movw FRAME_PREV_FCW(%rsp), %r11w
	movw %r11w, CTX_HOST_FCW(%r10)
	movl FRAME_PREV_MXCSR(%rsp), %r11d
	movl %r11d, CTX_HOST_MXCSR(%r10)
	/* the host's %fs back, whenever entry parked it: what entry parked is
	 * the truth, whether the guest ever swapped or a repair installed its
	 * pointer. */
#ifdef __ELF__
	movq mb_fs_swap@GOTPCREL(%rip), %r11
	cmpb $0, (%r11)
#else
	cmpb $0, mb_fs_swap(%rip)
#endif
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
#ifdef __APPLE__
	/* the undo below writes the thread's block through gs, whichever side
	 * of the boundary was running when the guest died. The bounds it copies
	 * back are in the 24 bytes just below this stack pointer, where a call
	 * would put its return address, so the call is made further down */
	leaq -256(%rsp), %rsp
	callq mb_gs_to_guest
	leaq 256(%rsp), %rsp
#endif
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

#ifdef __APPLE__
	.p2align 4
/* mb_gs_to_guest / mb_gs_to_host: swap this thread's gs base between the OS's
 * and the guest block, keeping every register (the arguments of an entry thunk
 * and the result of a call are in flight) and the flags. The base is set the
 * only way userspace can: the machine-dependent system call libsystem makes
 * for _thread_set_tsd_base, number 3, rdi the new base.
 *
 * to_guest asks C for the block (this thread's, made at mb_prepare_thread)
 * and so must run on the OS's gs; it does nothing when already on the guest's.
 * to_host reads the OS's base out of the guest block and does nothing when it
 * is not on one.
 *
 * Entry rsp % 16 == 8 as at any call; 10 words are saved, so the C call is
 * made with rsp % 16 == 0. */
	.globl mb_gs_to_guest
	.private_extern mb_gs_to_guest
mb_gs_to_guest:
	pushfq
	pushq %rax
	pushq %r11
	movq %gs:0, %rax
	movabsq $0x4d4247534d414731, %r11   /* MB_GS_MAGIC */
	cmpq %r11, %rax
	je 1f
	pushq %rdi
	pushq %rsi
	pushq %rdx
	pushq %rcx
	pushq %r8
	pushq %r9
	pushq %r10
	subq $8, %rsp                        /* rsp % 16 == 0 at the call */
	callq mb_gs_block_c
	addq $8, %rsp
	movq %rax, %rdi
	movl $0x3000003, %eax
	syscall
	popq %r10
	popq %r9
	popq %r8
	popq %rcx
	popq %rdx
	popq %rsi
	popq %rdi
1:	popq %r11
	popq %rax
	popfq
	ret

	.globl mb_gs_to_host
	.private_extern mb_gs_to_host
mb_gs_to_host:
	pushfq
	pushq %rax
	pushq %rcx
	pushq %rdx
	pushq %rdi
	pushq %r11
	movq %gs:0, %rax
	movabsq $0x4d4247534d414731, %rcx   /* MB_GS_MAGIC */
	cmpq %rcx, %rax
	jne 1f
	movq %gs:0x68, %rdi                  /* MB_TIB_HOST_GS */
	movl $0x3000003, %eax
	syscall
1:	popq %r11
	popq %rdi
	popq %rdx
	popq %rcx
	popq %rax
	popfq
	ret
#endif

#ifndef _WIN32
/* Linux: the guest's fault handler, run on the faulting thread's own stack.
 *
 * The signal handler used to call it itself, on the host's alternate signal
 * stack, and a handler that gave way to another guest thread (RPCS3's waits
 * for a flush) left its frames there for the next fault to build its own on
 * (2026-10-18). Now the signal handler only points the interrupted thread
 * here and returns: rsp is the thread's own, 128 bytes below where it was
 * (the red zone of the code that faulted), rdi and rsi are the handler's
 * arguments, and the rest of what this needs is in the thread's gs block
 * (MB_TIB_FAULT_*), the one base that is this thread's whatever %fs holds.
 * Every other register is the faulting code's, and all of them, the flags
 * and the vector state are given back before the instruction runs again.
 *
 * Two copies of one body: the guest's (a fault in guest code; runs with the
 * guest's %fs and counts as guest code to the fault handler) and the host's
 * (a fault in host code; calls the guest-entry thunk). */
	.macro FAULT_TRAMP name, host=0
	.globl \name
#ifdef __ELF__
	.hidden \name
	.type \name, @function
#else
	.private_extern \name
#endif
	.p2align 4
\name:
	pushq %gs:0x28          /* R-8: the faulting rip, where `ret` goes */
	pushq %gs:0x38          /* its rsi */
	pushq %gs:0x30          /* its rdi */
	pushq %gs:0x20          /* the handler */
	pushfq
	pushq %rax
	pushq %rcx
	pushq %rdx
	pushq %rbx
	pushq %rbp
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	movq %rsp, %rbx         /* the 14 words above; the handler at 112(%rbx) */
	movq %rdi, %r12
	movq %rsi, %r13
	subq mb_xsave_size(%rip), %rsp
	andq $-64, %rsp
	movq mb_xsave_mask(%rip), %rax
	testq %rax, %rax
	jz 1f
	movq %rax, %rdx
	shrq $32, %rdx
	xorl %ecx, %ecx         /* xrstor wants the header that xsave leaves alone zero */
	movq %rcx, 512(%rsp)
	movq %rcx, 520(%rsp)
	movq %rcx, 528(%rsp)
	movq %rcx, 536(%rsp)
	movq %rcx, 544(%rsp)
	movq %rcx, 552(%rsp)
	movq %rcx, 560(%rsp)
	movq %rcx, 568(%rsp)
	xsave64 (%rsp)
	jmp 2f
1:	fxsave64 (%rsp)
2:	movq %r12, %rdi
	movq %r13, %rsi
	cld
#ifdef __APPLE__
	.if \host
	/* a fault in host code: the signal handler put the thread on the guest
	 * block for the words above; the guest-entry thunk below is host code,
	 * and leaves the thread where it found it, so go back to the OS's */
	movq %gs:0x60, %r14     /* MB_TIB_SELF: the words below are written through it */
	callq mb_gs_to_host
	.endif
#endif
	callq *112(%rbx)
	testl %eax, %eax
	jnz 3f
#ifdef __APPLE__
	.if \host
	movq %r12, 0x40(%r14)   /* not the guest's: the retry is an unhandled fault */
	.else
	movq %r12, %gs:0x40
	.endif
#else
	movq %r12, %gs:0x40     /* not the guest's: the retry is an unhandled fault */
#endif
3:	movq mb_xsave_mask(%rip), %rax
	testq %rax, %rax
	jz 4f
	movq %rax, %rdx
	shrq $32, %rdx
	xrstor64 (%rsp)
	jmp 5f
4:	fxrstor64 (%rsp)
5:	movq %rbx, %rsp
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rbp
	popq %rbx
	popq %rdx
	popq %rcx
	popq %rax
	popfq
	movq 8(%rsp), %rdi      /* no flag may change from here */
	movq 16(%rsp), %rsi
	leaq 24(%rsp), %rsp
	retq $128               /* to the faulting rip, rsp where it was */
	.globl \name\()_end
#ifdef __ELF__
	.hidden \name\()_end
#else
	.private_extern \name\()_end
#endif
\name\()_end:
#ifdef __ELF__
	.size \name, \name\()_end - \name
#endif
	.endm

	FAULT_TRAMP mb_fault_tramp_guest
	FAULT_TRAMP mb_fault_tramp_host, 1
#endif

#ifdef __ELF__
	.section .note.GNU-stack,"",@progbits
#endif
