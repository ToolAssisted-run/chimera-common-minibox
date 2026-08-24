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
static bool g_initialized = false;

static uintptr_t mirror_of(const mb_block *b, uintptr_t guest) {
	return guest - b->addr.start + b->mirror.start;
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
	if (!(s == MB_ST_RW || s == MB_ST_RWX || s == MB_ST_RWSTACK)) {
		__builtin_trap();
		return false;
	}
	mb_page_maybe_snapshot(p, mirror_of(b, page_start));
	p->dirty = true;
	mb_range r = { page_start, MB_PAGESIZE };
	if (mb_pal_protect(r, mb_page_native_prot(p)) != 0) { __builtin_trap(); abort(); }
	return true;
}

#ifndef _WIN32
/* ---- Linux: SIGSEGV via sigaction, chaining to the previous handler ---- */
#include <signal.h>
#include <ucontext.h>
static struct sigaction g_old_sa;

static void handler(int sig, siginfo_t *info, void *ucontext) {
	uintptr_t fault = (uintptr_t)info->si_addr;
	ucontext_t *uc = (ucontext_t *)ucontext;
	bool write = (uc->uc_mcontext.gregs[REG_ERR] & 2) != 0;
	bool rethrow = !write || !trip(fault);
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
	ss.ss_size = 64 * 1024;
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

static LONG CALLBACK veh(EXCEPTION_POINTERS *ep) {
	DWORD code = ep->ExceptionRecord->ExceptionCode;
	if (code == STATUS_GUARD_PAGE_VIOLATION) {
		/* A cothread/RWStack guard trip. If it is ours, dirtiness is recovered
		 * lazily via get_stack_dirty; the kernel already cleared the guard bit.
		 * Return without taking any lock (the handler's own stack may be
		 * growing into another guard page, which would deadlock). */
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	if (code != STATUS_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
	/* ExceptionInformation[0]: 0 read, 1 write, 8 DEP */
	bool write = ep->ExceptionRecord->ExceptionInformation[0] == 1;
	uintptr_t fault = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
	if (write && trip(fault)) return EXCEPTION_CONTINUE_EXECUTION;

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
