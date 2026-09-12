/* Dirty-page fault handler. A logically-writable clean page is mapped read-only
 * (or, on Windows, a guard page); its first write faults here, we snapshot the
 * pre-write content, mark dirty, and reprotect writable. Faithful port of
 * BizHawk waterboxhost src/memory_block/tripguard.rs. Linux path is runtime-validated;
 * Windows path is cross-compile-checked (mingw) but not runtime-validated here. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "minibox_internal.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Single-threaded host, so a plain array + no lock is sufficient. (The Rust
 * reference guards a global block list with a mutex for multi-core hosting.) */
#define MAX_BLOCKS 64
static mb_block *g_blocks[MAX_BLOCKS];
static int g_nblocks = 0;

/* Where an address IS, in the words the layout uses.
 *
 * "inside a registered block, page 20768" is arithmetic somebody has to do by
 * hand against the core's own ELF before it means anything - and the answer is
 * usually the difference between a bug and a symptom. The layout knows, so it
 * says: the region, the offset into it, and for the two guest stacks whether
 * the address is in the guard at the bottom, which is what a stack that ran out
 * looks like.
 *
 * Set by mb_host_new. One machine runs at a time; a second host replaces it,
 * which is right, because its layout is the live one. */
static const mb_layout *g_layout = NULL;

void mb_tripguard_set_layout(const mb_layout *l) { g_layout = l; }

static void say_region(uintptr_t a) {
	const mb_layout *L = g_layout;
	if (L == NULL) return;
	static const char *names[] = { "elf", "main stack", "alt stack", "sbrk",
	                               "sealed heap", "invisible heap", "plain heap", "mmap arena" };
	/* walked as an array, so the struct had better be exactly those eight */
	_Static_assert(sizeof(mb_layout) == 8 * sizeof(mb_range),
	               "mb_layout must be the eight ranges say_region names, in that order");
	const mb_range *rs = &L->elf;
	for (int i = 0; i < 8; i++) {
		if (!mb_range_contains(rs[i], a)) continue;
		mb_diag(" in the %s +0x%llx", names[i], (unsigned long long)(a - rs[i].start));
		/* elf.c guards the low 4 pages of each guest stack; landing there is a
		 * stack that ran out, not a wild pointer */
		if ((i == 1 || i == 2) && a < rs[i].start + MB_PAGESIZE * 4)
			mb_diag(" - THE GUARD AT ITS BOTTOM: this stack overflowed");
		return;
	}
	mb_diag(" in no region of the layout");
}

static bool g_initialized = false;

static uintptr_t mirror_of(const mb_block *b, uintptr_t guest) {
	return guest - b->addr.start + b->mirror.start;
}

/* The guest's own fault handler, when it exports one (GuestFaultHandler,
 * resolved at activation). A guest may protect pages of its own block and
 * expect the first access to tell it so - an emulator's texture cache watches
 * guest memory exactly that way - and this is how it hears: called on the
 * faulting thread with the address and whether the access was a write; a
 * nonzero return means the guest changed the protection and the access is
 * retried. Faults on pages the guest never protected are not its business. */
static mb_guest_fault_fn g_guest_fault;

void mb_tripguard_set_guest_fault_handler(mb_guest_fault_fn fn) { g_guest_fault = fn; }

#ifdef MB_HAVE_FSBASE
/* Is the instruction we are about to resume the guest's own? That is a property
 * of the faulting rip, not of any register - which matters, because the register
 * we would otherwise ask (%fs) is the one under suspicion in here. The guest's
 * code lives inside a registered block; host code never does.
 *
 * No stack protector: this runs from a fault handler, and that check reads
 * %fs:0x28, which is exactly what is not yet safe. */
__attribute__((no_stack_protector))
static bool rip_in_guest(uintptr_t rip) {
	for (int i = 0; i < g_nblocks; i++)
		if (mb_range_contains(g_blocks[i]->addr, rip)) return true;
	return false;
}

/* Testing hook, for hosts that do NOT drop the base: pretend one did, so the
 * repair below is exercised on a machine where the bug cannot happen. */
__attribute__((no_stack_protector))
static bool drop_fs_for_test(void) {
	static int cached = -1;
	if (cached < 0) cached = getenv("MB_DROP_FS_ON_FAULT") ? 1 : 0;
	return cached == 1;
}

/* Leaving a fault handler back into guest code: install the guest's thread
 * pointer, whatever the register happens to hold now.
 *
 * The report has to be made from the HOST's %fs - fprintf reads its own thread
 * locals through %fs on Linux - which is why it is sandwiched here rather than
 * written where it reads more naturally. On Windows the host's is 0, and that
 * is the correct value to hold while host code runs there. */
__attribute__((no_stack_protector))
static void mb_restore_guest_fs(uintptr_t at_fault) {
	if (drop_fs_for_test()) at_fault = 0;
	/* What %fs held WHEN THE GUEST FAULTED, sampled by the caller before it
	 * swapped anything - reading it here would only report the handler's own
	 * swap back to the host.
	 *
	 * mb_early_tp is not a loss either: musl swaps thread_area in userspace,
	 * so %fs legitimately still holds the stand-in pointer until the next
	 * boundary, and installing the real one here is right, and silent. */
	if (at_fault != mb_guest_ctx->thread_area && at_fault != mb_early_tp) {
		static bool reported = false;
		if (!reported) {   /* once: this path runs thousands of times a second */
			reported = true;
			mb_wrfsbase(mb_guest_ctx->host_fs);
			fprintf(stderr, "miniBox: the OS does not keep the guest %%fs (it is "
			                "lost at a context switch, not at a fault); reinstalling it\n");
			fflush(stderr);
		}
	}
	mb_wrfsbase(mb_guest_ctx->thread_area);
}
#endif

static mb_block *owner_of(uintptr_t addr) {
	for (int i = 0; i < g_nblocks; i++)
		if (mb_range_contains(g_blocks[i]->addr, addr)) return g_blocks[i];
	return NULL;
}

/* A fault on a page the guest protected below what it could have: read-only
 * or no-access by the guest's own mprotect. Not a tracked clean page (that is
 * trip's), not a free page (nobody's). */
static bool guest_protected(uintptr_t addr, bool write) {
	mb_block *b = owner_of(addr);
	if (!b) return false;
	uint8_t s = b->pages[(addr - b->addr.start) >> MB_PAGESHIFT].status;
	if (s == MB_ST_NONE) return true;
	if (write && (s == MB_ST_R || s == MB_ST_RX)) return true;
	return false;
}

static bool ask_guest(uintptr_t addr, bool write) {
	if (!g_guest_fault || !guest_protected(addr, write)) return false;
	return g_guest_fault((uint64_t)addr, write ? 1 : 0) != 0;
}

/* Shared: handle a write fault at addr. Returns true if handled. */
static bool trip(uintptr_t addr) {
	mb_block *b = NULL;
	for (int i = 0; i < g_nblocks; i++)
		if (mb_range_contains(g_blocks[i]->addr, addr)) { b = g_blocks[i]; break; }
	if (!b) return false;
	uintptr_t page_start = addr & ~(uintptr_t)MB_PAGEMASK;
	size_t pi = (addr - b->addr.start) >> MB_PAGESHIFT;
	mb_page *p = &b->pages[pi];
	uint8_t s = p->status;
	if (!(s == MB_ST_RW || s == MB_ST_RWX || s == MB_ST_RWSTACK))
		return false;  /* not a tracked clean page: the guest's, or nobody's */
	/* Order matters: the epoch wants what the page held before THIS write, and
	 * so does the baseline the first time round. Both read the same bytes, so
	 * both must run before the write is let through. */
	mb_block_epoch_capture(b, pi, mirror_of(b, page_start));
	mb_page_maybe_snapshot(p, mirror_of(b, page_start));
	mb_block_note_dirty(b, pi, true);
	mb_range r = { page_start, MB_PAGESIZE };
	if (mb_pal_protect(r, mb_page_native_prot(p)) != 0) { __builtin_trap(); abort(); }
	/* It is writable from here, so the next epoch has to hold it again. Only a
	 * bit: this is a signal handler. */
	mb_block_note_unheld(b, pi);
	return true;
}

#ifndef _WIN32
/* ---- Linux: SIGSEGV via sigaction, chaining to the previous handler ---- */
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
static struct sigaction g_old_sa;

static void handler_inner(int sig, siginfo_t *info, void *ucontext);

/* The host's %fs must be back before this touches anything.
 *
 * While a guest with its own thread pointer runs, %fs is the GUEST's - that is
 * the whole point of the swap - and a fault can arrive at any instruction. The
 * handler is host C: it reads errno, it calls into libc, and every one of those
 * goes through %fs. Running it on the guest's thread pointer means the host
 * reads and writes the guest's TLS block instead of its own.
 *
 * On Linux that survived by accident, because the guest's block happens to sit
 * where glibc keeps spare static TLS. On Windows the host's %fs is nobody's and
 * the same code dies on the guest's first faulting write - which, since sealing
 * marks every page clean, is immediately.
 *
 * No stack protector on this frame: that check itself reads %fs:0x28, which is
 * precisely what is not yet safe here. */
__attribute__((no_stack_protector))
static void handler(int sig, siginfo_t *info, void *ucontext) {
#ifdef MB_HAVE_FSBASE
	/* Only a fault in guest code, which the rip says and %fs does not: a
	 * frontend has many threads faulting for their own reasons, and one of
	 * them must be left exactly as it arrived. Asking the rip rather than
	 * rdfsbase also means this still works when %fs has already been lost -
	 * see the Windows handler below, where that is the normal case. */
	const bool guest_rip = mb_fs_swap && mb_guest_ctx
	                       && rip_in_guest((uintptr_t)((ucontext_t *)ucontext)
	                                       ->uc_mcontext.gregs[REG_RIP]);
	const uintptr_t fs_at_fault = guest_rip ? mb_rdfsbase() : 0;
	if (guest_rip && mb_guest_ctx->host_fs) mb_wrfsbase(mb_guest_ctx->host_fs);
	handler_inner(sig, info, ucontext);
	/* Back to the guest's, from the value the entry thunk recorded rather than
	 * from whatever was in the register on the way in. Same value on a host
	 * that preserves the base across a signal, and the right one on a host
	 * that does not. */
	if (guest_rip) mb_restore_guest_fs(fs_at_fault);
#else
	handler_inner(sig, info, ucontext);
#endif
}


/* A fault INSIDE the fault handler, which is how this used to die in silence.
 *
 * sa_mask is sigfillset, so SIGSEGV is blocked while the handler runs; a second
 * one is then force-delivered with the default action and the process is gone
 * before a line of diagnosis reaches anyone - no banner, no minibox-diag.log,
 * nothing but "Segmentation fault". Both addresses are exactly what a person
 * needs, so they are said here, with write(2) and a hand-rolled formatter
 * because nothing in stdio is safe on this path.
 *
 * Then the handler is put back to SIG_DFL and the inner fault is allowed to
 * happen again, so the process still dies the way it would have (core file
 * included) rather than being papered over. */
static __thread int g_fault_depth;
static __thread uintptr_t g_outer_fault, g_outer_rip;

/* The last faults, in a file, for the crash that leaves nothing behind.
 *
 * A fault the kernel cannot deliver - SIGSEGV already blocked, or a signal
 * frame that will not fit - kills the process before any handler runs, so the
 * evidence has to have been written BEFORE the fault that matters. Set
 * MB_FAULT_TRAIL to a path and every fault leaves four words in a ring there;
 * read it after the process is gone and the last entries are where it was.
 * Off unless asked for, and three stores when on. */
#define MB_TRAIL_SLOTS 64
static volatile uint64_t *g_trail;  /* [0] = count, then 4 words per slot */

static void trail_open(void) {
	const char *path = getenv("MB_FAULT_TRAIL");
	if (path == NULL || *path == '\0') return;
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return;
	const size_t bytes = (1 + MB_TRAIL_SLOTS * 4) * sizeof(uint64_t);
	if (ftruncate(fd, (off_t)bytes) == 0) {
		void *m = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (m != MAP_FAILED) g_trail = (volatile uint64_t *)m;
	}
	close(fd);
}

static volatile uint64_t *g_trail_slot;

static void trail_add(uintptr_t fault, uintptr_t rip, uintptr_t rsp, int write) {
	if (g_trail == NULL) return;
	uint64_t n = g_trail[0]++;
	volatile uint64_t *slot = g_trail + 1 + (n % MB_TRAIL_SLOTS) * 4;
	slot[0] = fault;
	slot[1] = rip;
	slot[2] = rsp;
	slot[3] = (uint64_t)write;
	g_trail_slot = slot;
}

/* How far the handler got before it stopped being alive to say so. */
static void trail_stage(unsigned stage) {
	if (g_trail_slot != NULL) g_trail_slot[3] = (g_trail_slot[3] & 0xff) | ((uint64_t)stage << 8);
}

static void sigsafe_report_nested(uintptr_t inner_fault, uintptr_t inner_rip) {
	static const char hex[] = "0123456789abcdef";
	char buf[192];
	size_t n = 0;
	const char *lead = "miniBox: a fault INSIDE the fault handler; the host cannot survive it.\n  outer ";
	for (const char *p = lead; *p; p++) buf[n++] = *p;
	const uintptr_t v[4] = { g_outer_fault, g_outer_rip, inner_fault, inner_rip };
	for (int i = 0; i < 4; i++) {
		const char *label = (i == 0 || i == 2) ? "addr=0x" : " rip=0x";
		for (const char *p = label; *p; p++) buf[n++] = *p;
		for (int sh = 60; sh >= 0; sh -= 4) buf[n++] = hex[(v[i] >> sh) & 0xf];
		if (i == 1) { const char *s2 = "\n  inner "; for (const char *p = s2; *p; p++) buf[n++] = *p; }
	}
	buf[n++] = '\n';
	ssize_t ignored = write(2, buf, n);
	(void)ignored;
}

static void handler_inner(int sig, siginfo_t *info, void *ucontext) {
	uintptr_t fault = (uintptr_t)info->si_addr;
	ucontext_t *uc = (ucontext_t *)ucontext;
	bool write = (uc->uc_mcontext.gregs[REG_ERR] & 2) != 0;
	if (g_fault_depth > 0) {
		sigsafe_report_nested(fault, (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]);
		signal(SIGSEGV, SIG_DFL);
		return;  /* the instruction runs again and the default action takes it */
	}
	g_fault_depth++;
	g_outer_fault = fault;
	g_outer_rip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
	trail_add(fault, (uintptr_t)uc->uc_mcontext.gregs[REG_RIP],
	          (uintptr_t)uc->uc_mcontext.gregs[REG_RSP], write ? 1 : 0);
	trail_stage(1);
	bool tripped = write && trip(fault);
	trail_stage(2);
	bool asked = tripped ? false : ask_guest(fault, write);
	trail_stage(3);
	bool rethrow = !tripped && !asked;
	if (rethrow) {
		/* Mirror the Windows path: say what was asked for and whether any block
		 * owns the address before the process dies with nothing to debug. */
		mb_block *owner = NULL;
		for (int i = 0; i < g_nblocks; i++)
			if (mb_range_contains(g_blocks[i]->addr, fault)) { owner = g_blocks[i]; break; }
		mb_diag_banner("unhandled fault");
		mb_diag("[tripguard] unhandled fault: addr=%p %s rip=%p, %s",
		        (void *)fault, write ? "write" : "read/exec",
		        (void *)uc->uc_mcontext.gregs[REG_RIP],
		        owner ? "inside a registered block" : "OUTSIDE every registered block");
		if (owner) {
			size_t pi = (fault - owner->addr.start) >> MB_PAGESHIFT;
			mb_diag(" (page %zu status=%u dirty=%u invisible=%u)",
			        pi, owner->pages[pi].status, owner->pages[pi].dirty, owner->pages[pi].invisible);
		}
		say_region(fault);
		mb_diag(" [%d block(s) registered]\n", g_nblocks);
	}
	g_fault_depth--;
	if (rethrow) {
		if (g_old_sa.sa_flags & SA_SIGINFO)
			g_old_sa.sa_sigaction(sig, info, ucontext);
		else if (g_old_sa.sa_handler == SIG_DFL || g_old_sa.sa_handler == SIG_IGN) {
			signal(sig, SIG_DFL);
			raise(sig);
		} else
			g_old_sa.sa_handler(sig);
	}
}

/* SA_ONSTACK only helps if an alternate signal stack exists. The .NET runtime
 * installs one per thread (which is why the BizHawk reference never needed
 * this), but a plain C host has none - and without it, a faulting PUSH onto a
 * clean (read-only-mapped) tracked page is fatal: the kernel cannot deliver
 * the signal onto the very stack that faulted. Guest green-thread stacks are
 * ordinary tracked pages, so this case is real. One altstack per host thread
 * that runs guest code; installed for the current thread here, and
 * mb_tripguard_ensure_altstack() lets other entry points opt in. */
void mb_tripguard_ensure_altstack(void) {
	stack_t ss_old;
	if (sigaltstack(NULL, &ss_old) == 0 && !(ss_old.ss_flags & SS_DISABLE) && ss_old.ss_sp)
		return;  /* this thread already has one */
	stack_t ss;
	memset(&ss, 0, sizeof(ss));
	ss.ss_size = 1024 * 1024;  /* a guest fault handler may run real code here */
	ss.ss_sp = malloc(ss.ss_size);
	ss.ss_flags = 0;
	if (!ss.ss_sp || sigaltstack(&ss, NULL) != 0) { perror("miniBox sigaltstack"); abort(); }
}

static void initialize(void) {
	trail_open();
	mb_tripguard_ensure_altstack();
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_ONSTACK | SA_SIGINFO;
	sigfillset(&sa.sa_mask);
	if (sigaction(SIGSEGV, &sa, &g_old_sa) != 0) { perror("miniBox sigaction"); abort(); }
}

#else
/* ---- Windows: a vectored exception handler ---- */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static LONG CALLBACK veh_inner(EXCEPTION_POINTERS *ep);

/* Windows does not keep a user-mode FS base at all, and not merely across a
 * fault. That is worth stating precisely, because the weaker version of it was
 * believed here for a while and the repair built on it cannot work.
 *
 * Measured on Windows 11 with a five-line program: wrfsbase, then plain
 * computation - no fault, no syscall, no yield of any kind. The base survived
 * an explicit SwitchToThread, was gone after Sleep(1), and was gone after 47 ms
 * and 16 million iterations of arithmetic, which is one scheduler quantum.
 * Windows restores %fs for an x64 user thread the way it restores the rest of
 * the register file, except that it believes the answer is always 0.
 *
 * So the loss has no event to hang a repair on. The base is not dropped BY the
 * fault; it was already gone, at whatever instruction the scheduler picked, and
 * the fault being handled here is usually the guest's next thread-local read
 * arriving at a small negative address. A guest that reads one often dies
 * within a second: Ruffle's in-guest Mesa reads %fs:-0x30 (_glapi_tls_Dispatch)
 * on every GL call, and faulted at 0xffffffffffffffd0.
 *
 * The repair therefore happens HERE, on the way IN, rather than only on the way
 * out: if guest code faulted while %fs held anything but the guest's thread
 * pointer, put the pointer back and retry the instruction. It faulted before it
 * had any architectural effect, so retrying it is exactly right. A fault that is
 * genuinely the guest's own arrives back immediately with %fs already correct,
 * this test is false the second time, and it is handled below as it always was -
 * which is what bounds the retry to one pass.
 *
 * The way OUT still restores as well, for the fault that does drop the base and
 * for the OS that keeps it, where the write is a no-op. */
__attribute__((no_stack_protector))
static LONG CALLBACK veh(EXCEPTION_POINTERS *ep) {
#ifdef MB_HAVE_FSBASE
	const bool guest_rip = mb_fs_swap && mb_guest_ctx
	                       && rip_in_guest((uintptr_t)ep->ContextRecord->Rip);
	const uintptr_t fs_at_fault = guest_rip ? mb_rdfsbase() : 0;
	/* The real register, not drop_fs_for_test's pretend one: that hook forces
	 * the answer unconditionally, and a forced answer here would re-fault into
	 * the same retry for ever. The cost is that this path is exercised on
	 * Windows only, which is also the only place it can happen. */
	if (guest_rip && fs_at_fault != mb_guest_ctx->thread_area
	    && fs_at_fault != mb_early_tp) {
		mb_restore_guest_fs(fs_at_fault);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	LONG r = veh_inner(ep);
	if (guest_rip && r == EXCEPTION_CONTINUE_EXECUTION) mb_restore_guest_fs(fs_at_fault);
	return r;
#else
	return veh_inner(ep);
#endif
}

static LONG CALLBACK veh_inner(EXCEPTION_POINTERS *ep) {
	DWORD code = ep->ExceptionRecord->ExceptionCode;
	if (code == STATUS_GUARD_PAGE_VIOLATION) {
		/* No page of a block is a guard page - see mb_page_native_prot - so
		 * this is the host's own stack growing, and the kernel has already done
		 * the work by clearing the bit. Returned without taking any lock,
		 * because the stack that is growing may be this handler's. */
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	if (code != STATUS_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
	/* ExceptionInformation[0]: 0 read, 1 write, 8 DEP */
	bool write = ep->ExceptionRecord->ExceptionInformation[0] == 1;
	uintptr_t fault = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
	if (write && trip(fault)) return EXCEPTION_CONTINUE_EXECUTION;
	if (ask_guest(fault, write)) return EXCEPTION_CONTINUE_EXECUTION;

	/* About to become an unhandled access violation, i.e. an instant process
	 * death with nothing to debug. Say what was asked for and whether any block
	 * owns the address - the difference between "the guest touched something it
	 * should not have" and "dirty-page tracking did not recognise its own
	 * memory" is the whole diagnosis. */
	{
		mb_block *owner = NULL;
		for (int i = 0; i < g_nblocks; i++)
			if (mb_range_contains(g_blocks[i]->addr, fault)) { owner = g_blocks[i]; break; }
		mb_diag_banner("unhandled fault");
		mb_diag("[veh] unhandled fault: addr=%p access=%s rip=%p, %s",
		        (void *)fault,
		        ep->ExceptionRecord->ExceptionInformation[0] == 0 ? "read"
		          : ep->ExceptionRecord->ExceptionInformation[0] == 1 ? "write" : "execute",
		        (void *)ep->ContextRecord->Rip,
		        owner ? "inside a registered block" : "OUTSIDE every registered block");
		if (owner) {
			size_t pi = (fault - owner->addr.start) >> MB_PAGESHIFT;
			mb_diag(" (page %zu status=%u dirty=%u invisible=%u)",
			        pi, owner->pages[pi].status, owner->pages[pi].dirty, owner->pages[pi].invisible);
		}
		say_region(fault);
		mb_diag(" [%d block(s) registered]\n", g_nblocks);
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

static void initialize(void) {
	if (AddVectoredExceptionHandler(1 /* CALL_FIRST */, veh) == NULL) {
		fprintf(stderr, "miniBox: AddVectoredExceptionHandler failed\n");
		abort();
	}
}
#endif

void mb_tripguard_register(mb_block *b) {
	if (!g_initialized) { initialize(); g_initialized = true; }
	if (g_nblocks < MAX_BLOCKS) g_blocks[g_nblocks++] = b;
	else { fprintf(stderr, "miniBox: too many blocks registered\n"); abort(); }
}

void mb_tripguard_unregister(mb_block *b) {
	for (int i = 0; i < g_nblocks; i++)
		if (g_blocks[i] == b) { g_blocks[i] = g_blocks[--g_nblocks]; return; }
}
