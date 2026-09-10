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
			fprintf(stderr, "miniBox: the OS drops the guest %%fs across a fault; "
			                "reinstalling it on the way out\n");
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

/* The block and page an address belongs to, or NULL. */
static mb_page *page_of(uintptr_t addr, mb_block **out_block) {
	for (int i = 0; i < g_nblocks; i++) {
		if (!mb_range_contains(g_blocks[i]->addr, addr)) continue;
		if (out_block) *out_block = g_blocks[i];
		return &g_blocks[i]->pages[(addr - g_blocks[i]->addr.start) >> MB_PAGESHIFT];
	}
	return NULL;
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
	p->dirty = true;
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


static void handler_inner(int sig, siginfo_t *info, void *ucontext) {
	uintptr_t fault = (uintptr_t)info->si_addr;
	ucontext_t *uc = (ucontext_t *)ucontext;
	bool write = (uc->uc_mcontext.gregs[REG_ERR] & 2) != 0;
	bool rethrow = !(write && trip(fault)) && !ask_guest(fault, write);
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

/* Windows loses the guest's %fs across a fault.
 *
 * An exception here is delivered by the kernel, and the user-mode FS base does
 * not survive that round trip: the handler is entered, and the guest resumed,
 * with %fs back at 0. Nothing notices until the guest's next thread-local read,
 * which is why this took a real game to find - the small test movies are AVM1
 * and never reach the thread locals AVM2 verification keeps.
 *
 * So on Windows there is nothing to swap on the way IN. The host's %fs there is
 * 0, nobody's; host code reaches its thread locals through the TEB on %gs and
 * does not care what %fs holds. All that is needed is to put the guest's back
 * before resuming a guest instruction - which is a no-op on any OS that kept
 * it, and the whole fix on this one. */
__attribute__((no_stack_protector))
static LONG CALLBACK veh(EXCEPTION_POINTERS *ep) {
#ifdef MB_HAVE_FSBASE
	const bool guest_rip = mb_fs_swap && mb_guest_ctx
	                       && rip_in_guest((uintptr_t)ep->ContextRecord->Rip);
	const uintptr_t fs_at_fault = guest_rip ? mb_rdfsbase() : 0;
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
		uintptr_t fault = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
		mb_page *p = page_of(fault, NULL);

		/* Not one of ours, or an RWStack page: leave it alone. An RWStack page's
		 * dirtiness is recovered lazily via get_stack_dirty - the kernel has
		 * already cleared the guard bit - and this returns without taking any
		 * lock, because the handler's own stack may be growing into another
		 * guard page, which would deadlock. */
		if (p == NULL || p->status == MB_ST_RWSTACK) return EXCEPTION_CONTINUE_EXECUTION;

		/* A clean MB_ST_RW page. The kernel has just cleared the guard bit,
		 * which means the page is WRITABLE from this instant - so doing nothing
		 * would let every later write through untracked, and a savestate would
		 * be missing them. The bookkeeping has to happen here, now.
		 *
		 * ExceptionInformation[0]: 0 read, 1 write, 8 execute. */
		bool write = ep->ExceptionRecord->ExceptionInformation[0] == 1;

		/* A read of a clean page leaves it clean, and it wants its read-only
		 * protection back so that later reads are free and a later write still
		 * faults. Unless the page is the one the stack is in: there a later
		 * write fault could not be delivered, which is the whole reason this
		 * page was a guard page, so it is dirtied now instead. A stack page
		 * about to be read is about to be written. */
		uintptr_t rsp = (uintptr_t)ep->ContextRecord->Rsp;
		uintptr_t page = fault & ~(uintptr_t)MB_PAGEMASK;
		bool is_stack = rsp >= page - MB_PAGESIZE && rsp < page + 2 * MB_PAGESIZE;

		if (write || is_stack) {
			if (!trip(fault)) {
				/* Nothing claimed it and the guard is gone: put the page back
				 * as it was, or the next write is invisible. */
				mb_range r = { page, MB_PAGESIZE };
				mb_pal_protect(r, mb_page_native_prot(p));
			}
		} else {
			mb_range r = { page, MB_PAGESIZE };
			if (mb_pal_protect(r, MB_PROT_R) != 0) { __builtin_trap(); abort(); }
		}
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
