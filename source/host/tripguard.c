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
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

/* The block LIST changes only when a machine is created or destroyed, on the
 * thread that does that, so a plain array serves it. (The Rust reference
 * guards it with a mutex for multi-core hosting.) The per-block TRACKING state
 * the handler writes is another matter: see mb_block_track_lock. */
#define MAX_BLOCKS 64
static mb_block *g_blocks[MAX_BLOCKS];
static int g_nblocks = 0;

/* Whether an instruction is the guest's own: guest code lives in a registered
 * block, host code never does. */
static bool code_in_guest(uintptr_t rip) {
	for (int i = 0; i < g_nblocks; i++)
		if (mb_range_contains(g_blocks[i]->addr, rip)) return true;
	return false;
}

/* A fault the guest's own code took, with a machine to charge it to: that is a
 * guest dying, which the host survives (mb_host_guest_death). Anything else - a
 * fault in host code, or with no machine running - is not, and stays fatal. */
static bool guest_can_die_here(uintptr_t rip) {
	return mb_guest_ctx != NULL && mb_guest_ctx->host_ptr != 0 && code_in_guest(rip);
}

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
 * which is right, because its layout is the live one.
 *
 * It is a pointer INTO the mb_host, so the host that set it must take it back
 * when it is destroyed, exactly as it takes back mb_guest_ctx. It did not, and
 * chimera#127 is what that costs: a PS3 core died, the machine was torn down,
 * and the next fault anywhere in the process - an ordinary one, the kind the
 * CLR raises and handles every day - reached say_region below, read the freed
 * host, and faulted INSIDE the handler. Windows answered that by running the
 * handler again, on the handler's own fault, for ever; the process died of a
 * stack overflow in msvcrt with nothing in the crash note about either fault. */
static const mb_layout *g_layout = NULL;

void mb_tripguard_set_layout(const mb_layout *l) { g_layout = l; }

void mb_tripguard_forget_layout(const mb_layout *l) {
	/* Only the layout that is still the live one: a host destroyed after a
	 * second has already started must not blind the second one's reports. */
	if (g_layout == l) g_layout = NULL;
}

const mb_layout *mb_tripguard_layout(void) { return g_layout; }

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

/* ---- what the handler is doing on THIS thread ------------------------------
 *
 * Two questions a fault has to answer before it is served: is the thread it
 * arrived on already inside the handler, and if so, doing what. The Linux
 * handler has asked the first since it learned to survive a fault inside
 * itself (g_fault_depth below: a nested fault is reported, and the process
 * dies as it would have, rather than dying silent). The Windows handler asked
 * neither. A vectored handler is an ordinary callback: it can be entered on
 * several threads at once - which is the tracking lock's business, see
 * mb_block_track_lock - and re-entered on one thread, for its own fault, with
 * no depth limit and no second chance (chimera#127: a handler faulting on its
 * own report, called again for that fault, until the stack ran out).
 *
 * Not every re-entry is a defect. The guest's own fault handler runs guest
 * code, which can write a held page and fault again, and that fault must be
 * served: handling may nest. What may NOT nest is the handler's own work - a
 * fault while it is TRACKING a page (it holds the tracking lock, so serving
 * the new fault would wait for ever) or while it is REPORTING one (the report
 * reads memory that may be exactly what is wrong). So a thread carries its
 * phase as well as its depth, and a fault that arrives in a phase that may not
 * nest, or deeper than any guest handler has business going, is said once and
 * passed on. The shared code below sets the phase on both hosts; on Linux the
 * signal is blocked for the handler's duration, so a fault in any phase is
 * fatal there and the phase only makes the last words precise.
 *
 * Per-thread storage: __thread on Linux, where the handler has the host's %fs
 * back before it reads anything. On Windows mingw's __thread is EMULATED
 * (__emutls_get_address), which allocates on a thread's first touch, and this
 * runs inside a fault handler on threads it has never seen - so a TLS slot,
 * which is a read of the TEB and nothing else. */
enum { MB_PHASE_NONE = 0, MB_PHASE_TRACK, MB_PHASE_GUEST, MB_PHASE_REPORT };
#define MB_FAULT_DEPTH_MOST 32   /* a guest handler that faults for ever is not served for ever */

#ifndef _WIN32
static __thread int g_fault_depth;
static __thread int g_fault_phase;
static int  fault_depth(void) { return g_fault_depth; }
static void fault_depth_set(int d) { g_fault_depth = d; }
static int  fault_phase(void) { return g_fault_phase; }
static void fault_phase_set(int p) { g_fault_phase = p; }
#else
static DWORD g_fault_tls = TLS_OUT_OF_INDEXES;   /* allocated in initialize(): depth << 8 | phase */
static uintptr_t fault_word(void) { return (uintptr_t)TlsGetValue(g_fault_tls); }
static int  fault_depth(void) { return (int)(fault_word() >> 8); }
static void fault_depth_set(int d) { TlsSetValue(g_fault_tls, (LPVOID)(((uintptr_t)d << 8) | (fault_word() & 0xff))); }
static int  fault_phase(void) { return (int)(fault_word() & 0xff); }
static void fault_phase_set(int p) { TlsSetValue(g_fault_tls, (LPVOID)((fault_word() & ~(uintptr_t)0xff) | (uintptr_t)p)); }
#endif

static const char *phase_name(int phase) {
	switch (phase) {
		case MB_PHASE_TRACK:  return "tracking a page";
		case MB_PHASE_GUEST:  return "in the guest's own fault handler";
		case MB_PHASE_REPORT: return "reporting a fault";
	}
	return "idle";
}

/* A fault the handler cannot serve because it is the handler's own, or one
 * thread's handling nested past any sense. Said ONCE per process, in one
 * sentence, because describing it at length is exactly what may just have
 * failed - and then passed on: on Windows to the process's own handlers, which
 * end in a crash note, on Linux to whoever had the signal. */
static void say_handler_fault_once(int phase, int depth, uintptr_t fault, uintptr_t rip) {
	static volatile int said;
	if (__atomic_exchange_n(&said, 1, __ATOMIC_ACQ_REL) != 0) return;
	mb_diag("\n=== miniBox: the fault handler faulted while %s ===\n"
	        "[veh] a fault at addr=%p rip=%p arrived on a thread that was already in the handler,"
	        " %s, %d deep, and is passed on undiagnosed. Serving it would wait for a lock this"
	        " thread holds, or describe memory that is what just failed; a handler that recurses"
	        " here dies of a stack overflow with neither fault in the crash note.\n",
	        phase_name(phase), (void *)fault, (void *)rip, phase_name(phase), depth);
}

static bool tracked_status(uint8_t s) {
	return s == MB_ST_RW || s == MB_ST_RWX || s == MB_ST_RWSTACK;
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
	/* guest code runs from here: a fault it takes on a held page is served */
	const int phase = fault_phase();
	fault_phase_set(MB_PHASE_GUEST);
	const bool handled = g_guest_fault((uint64_t)addr, write ? 1 : 0) != 0;
	fault_phase_set(phase);
	return handled;
}

/* Shared: handle a write fault at addr. Returns true if handled.
 *
 * Under the block's tracking lock, because what this writes - the epoch's
 * bitmap and count, the unheld bitmap, the dirty map, a snapshot - is shared
 * with every other thread that faults on this block and with the block
 * operations the guest's syscalls run. Two faults on two pages of one bitmap
 * word used to lose one of the two bits (test_tripguard). */
static bool trip(uintptr_t addr) {
	mb_block *b = owner_of(addr);
	if (!b) return false;
	uintptr_t page_start = addr & ~(uintptr_t)MB_PAGEMASK;
	size_t pi = (addr - b->addr.start) >> MB_PAGESHIFT;
	mb_page *p = &b->pages[pi];
	/* A look before the lock: most faults that are not this file's business
	 * are settled here. The status is read again under the lock. */
	if (!tracked_status(p->status)) return false;  /* not a tracked clean page: the guest's, or nobody's */
	/* The holder of the tracking lock faulting on the block it holds: a block
	 * operation touching the guest view it just protected, or this handler
	 * faulting on its own bookkeeping. Serving that would wait here for ever. */
	if (mb_block_track_held_here(b)) {
		say_handler_fault_once(MB_PHASE_TRACK, fault_depth(), addr, 0);
		return false;
	}
	const int phase = fault_phase();
	fault_phase_set(MB_PHASE_TRACK);
	mb_block_track_lock(b);
	bool tripped = false;
	if (tracked_status(p->status)) {
		/* Order matters: the epoch wants what the page held before THIS write,
		 * and so does the baseline the first time round. Both read the same
		 * bytes, so both must run before the write is let through. */
		mb_block_epoch_capture(b, pi, mirror_of(b, page_start));
		mb_page_maybe_snapshot(p, mirror_of(b, page_start));
		/* And a state being taken in the background wants the same bytes: this
		 * is the last moment they exist. One atomic exchange when no state is
		 * being taken, which is almost always. */
		mb_block_plan_capture(b, pi);
		mb_block_note_dirty(b, pi, true);
		mb_range r = { page_start, MB_PAGESIZE };
		if (mb_pal_protect(r, mb_page_native_prot(p)) != 0) { __builtin_trap(); abort(); }
		/* It is writable from here, so the next epoch has to hold it again.
		 * Only a bit: this is a signal handler. */
		mb_block_note_unheld(b, pi);
		tripped = true;
	}
	mb_block_track_unlock(b);
	fault_phase_set(phase);
	return tripped;
}

/* The faulting instruction and the registers that made its address.
 *
 * A fault inside the sandbox names no module - the guest is mapped memory, not
 * a loaded image - so an address and an rip are all the operating system's own
 * report contains, and generated code has no symbols to look up. The bytes are
 * worth more than the address: the crash that made this exist was a nop at the
 * faulting rip, which is impossible, and that was the clue - a stray relocation
 * had rewritten one byte of it into "add %bl,(%rdi)", a store to the first byte
 * of the machine's execution table. Reading that from a log took minutes; a
 * debugger had already cost a day.
 *
 * Nothing here allocates or locks: it runs in a fault handler. Sixteen bytes is
 * more than the longest x86 instruction, and if the code page itself is gone the
 * read faults again, which the nested-fault path already reports. */
#ifdef _WIN32
#include <windows.h>   /* VirtualQuery; include-guarded, the platform half includes it too */
#endif
static void say_code_and_regs(const unsigned char *ip, uintptr_t rsp, uintptr_t rbp, uintptr_t rax, uintptr_t rbx,
                              uintptr_t rcx, uintptr_t rdx, uintptr_t rsi, uintptr_t rdi, uintptr_t r8, uintptr_t r9,
                              uintptr_t r10, uintptr_t r11, uintptr_t r12, uintptr_t r13, uintptr_t r14, uintptr_t r15) {
	/* Registers FIRST: they cannot fault. The bytes can - a jump into garbage
	 * leaves rip at 0x2 or 0xf5, and reading there from inside this handler is
	 * a second fault that ends the report before it has said anything useful
	 * (issue #64 printed "code:" and died). */
	/* all of them: the one a bad address came from is never the one guessed
	 * (issue #64's read of 0x2b was 0x28 past an r15 this used to leave out) */
	mb_diag(" rip=%p rsp=%p rbp=%p\n rax=%p rbx=%p rcx=%p rdx=%p rsi=%p rdi=%p\n"
	        " r8=%p r9=%p r10=%p r11=%p r12=%p r13=%p r14=%p r15=%p\n",
	        (void *)ip, (void *)rsp, (void *)rbp, (void *)rax, (void *)rbx, (void *)rcx,
	        (void *)rdx, (void *)rsi, (void *)rdi, (void *)r8, (void *)r9, (void *)r10,
	        (void *)r11, (void *)r12, (void *)r13, (void *)r14, (void *)r15);
	if ((uintptr_t)ip < 0x10000) {
		mb_diag(" code: (rip is in the null region, nothing to read)\n");
		return;
	}
#ifdef _WIN32
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(ip, &mbi, sizeof mbi) != sizeof mbi || mbi.State != MEM_COMMIT
	    || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0
	    || (uintptr_t)ip + 16 > (uintptr_t)mbi.BaseAddress + mbi.RegionSize) {
		mb_diag(" code: (rip is not readable memory)\n");
		return;
	}
#endif
	mb_diag(" code:");
	for (int i = 0; i < 16; i++) mb_diag(" %02x", ip[i]);
	mb_diag("\n");
}

/* The guest's own return addresses, read off its stack.
 *
 * A guest ELF is ET_EXEC at a fixed base and a core package ships its core.wbx
 * unstripped, so every one of these is `addr2line -f -C -e core.wbx <addr>`
 * away from a name. Without them a fault report names the faulting function
 * and nothing about who called it, which for a crash inside a shared helper
 * (__dynamic_cast, memcpy, an allocator) says nothing at all.
 *
 * Only what is safe to read: the scan stays inside the one layout region rsp
 * is on, and on Windows asks the OS about each page first - a nested fault in
 * here would lose the report it is part of. */
#ifdef _WIN32
static bool page_readable(uintptr_t p) {
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery((void *)p, &mbi, sizeof mbi) != sizeof mbi) return false;
	if (mbi.State != MEM_COMMIT) return false;
	return (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;
}
#else
static bool page_readable(uintptr_t p) { (void)p; return true; }
#endif

static void say_guest_stack(uintptr_t rsp) {
	const mb_layout *L = g_layout;
	if (L == NULL || rsp == 0) return;
	/* Whichever region rsp is on - the two guest stacks, but also the mmap
	 * arena and the heaps, because a core that runs its own threads puts their
	 * stacks there. Staying inside that one region is what keeps the walk from
	 * stepping off into a guard page. */
	const mb_range *rs = &L->elf;
	const mb_range *stack = NULL;
	for (int i = 0; i < 8; i++)
		if (mb_range_contains(rs[i], rsp)) { stack = &rs[i]; break; }
	if (stack == NULL) { mb_diag(" guest stack: rsp is in no region of the layout, not walked\n"); return; }

	uintptr_t stop = rsp + MB_PAGESIZE * 16;
	if (stop > mb_range_end(*stack)) stop = mb_range_end(*stack);

	mb_diag(" guest stack (addr2line -f -C -e core.wbx):");
	int shown = 0;
	for (uintptr_t p = rsp; p + sizeof(uintptr_t) <= stop && shown < 24; p += sizeof(uintptr_t)) {
		/* the first word of each page, and the first of all, decides whether
		 * the page may be read at all; a page that may not ends the walk */
		if ((p == rsp || (p & MB_PAGEMASK) == 0) && !page_readable(p)) break;
		const uintptr_t v = *(const uintptr_t *)p;
		if (!mb_range_contains(L->elf, v)) continue;
		mb_diag(" +%llu:%llx", (unsigned long long)(p - rsp), (unsigned long long)v);
		shown++;
	}
	mb_diag(shown ? "\n" : " (nothing on it)\n");
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
	const bool guest_rip = mb_guest_ctx && mb_guest_ctx->fs_swap
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
/* g_fault_depth and g_fault_phase are above, shared with the Windows handler */
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
	char buf[256];
	size_t n = 0;
	const char *lead = "miniBox: a fault INSIDE the fault handler (";
	for (const char *p = lead; *p; p++) buf[n++] = *p;
	for (const char *p = phase_name(fault_phase()); *p; p++) buf[n++] = *p;
	const char *lead2 = "); the host cannot survive it.\n  outer ";
	for (const char *p = lead2; *p; p++) buf[n++] = *p;
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
		/* A fault in HOST code is not the guest's, and it is not necessarily the
		 * end: it goes on to whoever had the signal before - a runtime turns such
		 * faults into exceptions all day. Only a guest's own fault is one miniBox
		 * can call unhandled (issue #82 read a handled exception as four crashes). */
		const bool guest_code = code_in_guest((uintptr_t)uc->uc_mcontext.gregs[REG_RIP]);
		const bool handler_follows = (g_old_sa.sa_flags & SA_SIGINFO)
			|| (g_old_sa.sa_handler != SIG_DFL && g_old_sa.sa_handler != SIG_IGN);
		mb_diag_banner(guest_code ? "unhandled fault" : "a fault in host code");
		if (guest_code)
			mb_diag("[tripguard] unhandled fault: addr=%p %s rip=%p, %s",
			        (void *)fault, write ? "write" : "read/exec",
			        (void *)uc->uc_mcontext.gregs[REG_RIP],
			        owner ? "inside a registered block" : "OUTSIDE every registered block");
		else
			mb_diag("[tripguard] fault in host code, passed on %s: addr=%p %s rip=%p, %s",
			        handler_follows ? "to the handler that was there before (it may well be handled)"
			                        : "to the default action (the process ends)",
			        (void *)fault, write ? "write" : "read/exec",
			        (void *)uc->uc_mcontext.gregs[REG_RIP],
			        owner ? "inside a registered block" : "outside every registered block");
		if (owner) {
			size_t pi = (fault - owner->addr.start) >> MB_PAGESHIFT;
			mb_diag(" (page %zu status=%u dirty=%u invisible=%u)",
			        pi, owner->pages[pi].status, owner->pages[pi].dirty, owner->pages[pi].invisible);
		}
		say_region(fault);
		mb_diag(" [%d block(s) registered]\n", g_nblocks);
		say_code_and_regs((const unsigned char *)uc->uc_mcontext.gregs[REG_RIP],
		                  uc->uc_mcontext.gregs[REG_RSP], uc->uc_mcontext.gregs[REG_RBP],
		                  uc->uc_mcontext.gregs[REG_RAX], uc->uc_mcontext.gregs[REG_RBX],
		                  uc->uc_mcontext.gregs[REG_RCX], uc->uc_mcontext.gregs[REG_RDX],
		                  uc->uc_mcontext.gregs[REG_RSI], uc->uc_mcontext.gregs[REG_RDI],
		                  uc->uc_mcontext.gregs[REG_R8], uc->uc_mcontext.gregs[REG_R9],
		                  uc->uc_mcontext.gregs[REG_R10], uc->uc_mcontext.gregs[REG_R11],
		                  uc->uc_mcontext.gregs[REG_R12], uc->uc_mcontext.gregs[REG_R13],
		                  uc->uc_mcontext.gregs[REG_R14], uc->uc_mcontext.gregs[REG_R15]);
		if (guest_code) say_guest_stack((uintptr_t)uc->uc_mcontext.gregs[REG_RSP]);
		const uintptr_t rip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
		if (guest_can_die_here(rip)) {
			/* a hlt in user mode arrives as this fault: it is musl's a_crash(),
			 * which its allocator runs on finding the heap corrupt */
			const bool halted = *(const unsigned char *)rip == 0xf4;
			const bool escapable = halted
				? mb_host_guest_death_in_handler(mb_guest_ctx,
					"the core stopped itself after finding its own memory corrupt (a halt at %p)", (void *)rip)
				: mb_host_guest_death_in_handler(mb_guest_ctx,
					"the core crashed: it %s address %p (at %p)", write ? "wrote to" : "read or ran", (void *)fault, (void *)rip);
			if (escapable) {
				uc->uc_mcontext.gregs[REG_RSP] = (greg_t)mb_guest_ctx->esc_rsp;
				uc->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)&mb_guarded_escape;
				rethrow = false;
			}
		}
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

/* An illegal instruction (ud2) or an integer division by zero in guest code is
 * the guest dying too. Anyone else's - a runtime that turns SIGFPE into a
 * managed exception, say - goes to whoever had the signal before. */
static struct sigaction g_old_ill, g_old_fpe;

static void handler_other(int sig, siginfo_t *info, void *ucontext) {
	ucontext_t *uc = (ucontext_t *)ucontext;
	const uintptr_t rip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
	if (guest_can_die_here(rip)) {
#ifdef MB_HAVE_FSBASE
		/* host C from here on, which needs the host's %fs */
		if (mb_guest_ctx->fs_swap && mb_guest_ctx->host_fs) mb_wrfsbase(mb_guest_ctx->host_fs);
#endif
		mb_diag_banner(sig == SIGILL ? "the guest ran an illegal instruction" : "the guest divided by zero");
		say_code_and_regs((const unsigned char *)rip,
		                  uc->uc_mcontext.gregs[REG_RSP], uc->uc_mcontext.gregs[REG_RBP],
		                  uc->uc_mcontext.gregs[REG_RAX], uc->uc_mcontext.gregs[REG_RBX],
		                  uc->uc_mcontext.gregs[REG_RCX], uc->uc_mcontext.gregs[REG_RDX],
		                  uc->uc_mcontext.gregs[REG_RSI], uc->uc_mcontext.gregs[REG_RDI],
		                  uc->uc_mcontext.gregs[REG_R8], uc->uc_mcontext.gregs[REG_R9],
		                  uc->uc_mcontext.gregs[REG_R10], uc->uc_mcontext.gregs[REG_R11],
		                  uc->uc_mcontext.gregs[REG_R12], uc->uc_mcontext.gregs[REG_R13],
		                  uc->uc_mcontext.gregs[REG_R14], uc->uc_mcontext.gregs[REG_R15]);
		const bool escapable = sig == SIGILL
			? mb_host_guest_death_in_handler(mb_guest_ctx, "the core ran an illegal instruction at %p", (void *)rip)
			: mb_host_guest_death_in_handler(mb_guest_ctx, "the core divided by zero at %p", (void *)rip);
		if (escapable) {
				uc->uc_mcontext.gregs[REG_RSP] = (greg_t)mb_guest_ctx->esc_rsp;
				uc->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)&mb_guarded_escape;
			return;
		}
	}
	const struct sigaction *old = sig == SIGILL ? &g_old_ill : &g_old_fpe;
	if (old->sa_flags & SA_SIGINFO) old->sa_sigaction(sig, info, ucontext);
	else if (old->sa_handler == SIG_DFL || old->sa_handler == SIG_IGN) signal(sig, SIG_DFL);   /* the instruction runs again and the default takes it */
	else old->sa_handler(sig);
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
	struct sigaction other;
	memset(&other, 0, sizeof(other));
	other.sa_sigaction = handler_other;
	other.sa_flags = SA_ONSTACK | SA_SIGINFO;
	sigfillset(&other.sa_mask);
	if (sigaction(SIGILL, &other, &g_old_ill) != 0 || sigaction(SIGFPE, &other, &g_old_fpe) != 0) {
		perror("miniBox sigaction"); abort();
	}
}

#else
/* ---- Windows: a vectored exception handler ---- */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static LONG CALLBACK veh_inner(EXCEPTION_POINTERS *ep);
static LONG veh_access_violation(EXCEPTION_POINTERS *ep, bool write, uintptr_t fault);

/* One report at a time, and never a report inside a report.
 *
 * A vectored handler that faults is called again FOR ITS OWN FAULT, at the same
 * instruction, with a fresh set of frames on the same stack. There is no depth
 * limit and no second chance: it ends when the stack runs out, and what the
 * crash note then says is "stack overflow in msvcrt.dll", which is true and
 * useless - neither the handler's fault nor the fault it was reporting appears
 * anywhere in it. chimera#127 is that log: one line naming a perfectly ordinary
 * host fault, then fifteen hundred identical lines naming the handler faulting
 * on its own diagnosis, then a dead process.
 *
 * Handling may nest - the guest's own fault handler runs guest code, which can
 * trip a clean page and fault again, and that must be served. REPORTING may
 * not: it walks the layout, the block list, the bytes at rip and the guest
 * stack, any of which can be the thing that is wrong. So a fault that arrives
 * while a report is running is passed straight on, and said once, in the
 * plainest way there is, because saying more is exactly what just failed. */
static volatile LONG g_reporting;

/* Same-thread re-entry into a report is caught before this by the phase check
 * in veh_inner (MB_PHASE_REPORT); this is the cross-thread half - one report
 * at a time - and the phase is set here so the other half can see it. */
static bool report_begin(EXCEPTION_POINTERS *ep, int *phase_before) {
	if (InterlockedCompareExchange(&g_reporting, 1, 0) != 0) {
		say_handler_fault_once(MB_PHASE_REPORT, fault_depth(),
		                       (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1],
		                       (uintptr_t)ep->ContextRecord->Rip);
		return false;
	}
	*phase_before = fault_phase();
	fault_phase_set(MB_PHASE_REPORT);
	return true;
}

static void report_end(int phase_before) {
	fault_phase_set(phase_before);
	InterlockedExchange(&g_reporting, 0);
}

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
static LONG CALLBACK veh_fs(EXCEPTION_POINTERS *ep);

/* The per-thread state above is read through TlsGetValue, which writes the
 * thread's last-error value on the way, and the code that faulted may be about
 * to read that value: it is put back. */
__attribute__((no_stack_protector))
static LONG CALLBACK veh(EXCEPTION_POINTERS *ep) {
	const DWORD last_error = GetLastError();
	const LONG r = veh_fs(ep);
	SetLastError(last_error);
	return r;
}

__attribute__((no_stack_protector))
static LONG CALLBACK veh_fs(EXCEPTION_POINTERS *ep) {
#ifdef MB_HAVE_FSBASE
	const bool guest_rip = mb_guest_ctx && mb_guest_ctx->fs_swap
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
	if (code == STATUS_PRIVILEGED_INSTRUCTION || code == STATUS_ILLEGAL_INSTRUCTION) {
		/* A hlt or ud2 at a GUEST address is the guest stopping itself on purpose:
		 * musl's a_crash() is a hlt, and it is what the allocator runs when its
		 * own consistency check finds a corrupted heap. That kills the process
		 * with no access violation, so the report below never saw it and the
		 * log stayed silent about exactly the crash it was built for. Nothing is
		 * handled here - the process still dies - it is only said first. */
		uintptr_t rip = (uintptr_t)ep->ContextRecord->Rip;
		bool in_guest = false;
		for (int i = 0; i < g_nblocks; i++)
			if (mb_range_contains(g_blocks[i]->addr, rip)) { in_guest = true; break; }
		if (in_guest) {
			int phase_before;
			if (!report_begin(ep, &phase_before)) return EXCEPTION_CONTINUE_SEARCH;
			const CONTEXT *c = ep->ContextRecord;
			mb_diag_banner(code == STATUS_PRIVILEGED_INSTRUCTION ? "the guest halted itself" : "the guest hit an illegal instruction");
			mb_diag("[veh] %s at rip=%p - a hlt here is musl's a_crash(): the guest found its own state corrupt\n",
			        code == STATUS_PRIVILEGED_INSTRUCTION ? "privileged instruction" : "illegal instruction", (void *)rip);
			say_code_and_regs((const unsigned char *)c->Rip, (uintptr_t)c->Rsp, (uintptr_t)c->Rbp,
			                  (uintptr_t)c->Rax, (uintptr_t)c->Rbx, (uintptr_t)c->Rcx, (uintptr_t)c->Rdx,
			                  (uintptr_t)c->Rsi, (uintptr_t)c->Rdi, (uintptr_t)c->R8, (uintptr_t)c->R9,
			                  (uintptr_t)c->R10, (uintptr_t)c->R11, (uintptr_t)c->R12, (uintptr_t)c->R13,
			                  (uintptr_t)c->R14, (uintptr_t)c->R15);
			if (guest_can_die_here(rip)
			    && mb_host_guest_death_in_handler(mb_guest_ctx, code == STATUS_PRIVILEGED_INSTRUCTION
			           ? "the core stopped itself after finding its own memory corrupt (a halt at %p)"
			           : "the core ran an illegal instruction at %p", (void *)rip)) {
				ep->ContextRecord->Rsp = (DWORD64)mb_guest_ctx->esc_rsp;
				ep->ContextRecord->Rip = (DWORD64)(uintptr_t)&mb_guarded_escape;
				report_end(phase_before);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			report_end(phase_before);
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}
	if (code == STATUS_INTEGER_DIVIDE_BY_ZERO || code == STATUS_INTEGER_OVERFLOW) {
		const uintptr_t rip = (uintptr_t)ep->ContextRecord->Rip;
		if (guest_can_die_here(rip)) {
			int phase_before;
			if (!report_begin(ep, &phase_before)) return EXCEPTION_CONTINUE_SEARCH;
			const CONTEXT *c = ep->ContextRecord;
			mb_diag_banner("the guest divided by zero");
			say_code_and_regs((const unsigned char *)c->Rip, (uintptr_t)c->Rsp, (uintptr_t)c->Rbp,
			                  (uintptr_t)c->Rax, (uintptr_t)c->Rbx, (uintptr_t)c->Rcx, (uintptr_t)c->Rdx,
			                  (uintptr_t)c->Rsi, (uintptr_t)c->Rdi, (uintptr_t)c->R8, (uintptr_t)c->R9,
			                  (uintptr_t)c->R10, (uintptr_t)c->R11, (uintptr_t)c->R12, (uintptr_t)c->R13,
			                  (uintptr_t)c->R14, (uintptr_t)c->R15);
			if (mb_host_guest_death_in_handler(mb_guest_ctx, code == STATUS_INTEGER_DIVIDE_BY_ZERO
			        ? "the core divided by zero at %p" : "the core overflowed a division at %p", (void *)rip)) {
				ep->ContextRecord->Rsp = (DWORD64)mb_guest_ctx->esc_rsp;
				ep->ContextRecord->Rip = (DWORD64)(uintptr_t)&mb_guarded_escape;
				report_end(phase_before);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			report_end(phase_before);
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}
	if (code != STATUS_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
	/* ExceptionInformation[0]: 0 read, 1 write, 8 DEP */
	bool write = ep->ExceptionRecord->ExceptionInformation[0] == 1;
	uintptr_t fault = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
	/* Is this thread already in here, and may it nest? Mirrors the Linux
	 * handler's g_fault_depth, with the one difference that matters: there the
	 * signal is blocked and a nested fault is fatal; here a fault the guest's
	 * own handler takes is served, and only the handler's OWN work is not
	 * re-entered. See the phase notes above trip(). */
	{
		const int phase = fault_phase(), depth = fault_depth();
		if (phase == MB_PHASE_TRACK || phase == MB_PHASE_REPORT || depth >= MB_FAULT_DEPTH_MOST) {
			say_handler_fault_once(phase, depth, fault, (uintptr_t)ep->ContextRecord->Rip);
			return EXCEPTION_CONTINUE_SEARCH;
		}
		fault_depth_set(depth + 1);
	}
	const LONG r = veh_access_violation(ep, write, fault);
	fault_depth_set(fault_depth() - 1);
	return r;
}

static LONG veh_access_violation(EXCEPTION_POINTERS *ep, bool write, uintptr_t fault) {
	if (write && trip(fault)) return EXCEPTION_CONTINUE_EXECUTION;
	if (ask_guest(fault, write)) return EXCEPTION_CONTINUE_EXECUTION;

	/* Not miniBox's to handle. Say what was asked for and whether any block owns
	 * the address - the difference between "the guest touched something it
	 * should not have" and "dirty-page tracking did not recognise its own
	 * memory" is the whole diagnosis.
	 *
	 * Only a fault in the GUEST's code is one miniBox can call unhandled. A
	 * vectored handler runs first, so a fault in host code still goes on to the
	 * process's own exception handlers, which catch such things routinely - the
	 * CLR turns them into NullReferenceException, and re-raises through
	 * KernelBase, so one handled exception used to be logged as two "unhandled"
	 * faults (issue #82). If nobody handles it, the crash note says so. */
	{
		int phase_before;
		if (!report_begin(ep, &phase_before)) return EXCEPTION_CONTINUE_SEARCH;
		mb_block *owner = NULL;
		for (int i = 0; i < g_nblocks; i++)
			if (mb_range_contains(g_blocks[i]->addr, fault)) { owner = g_blocks[i]; break; }
		const bool guest_code = code_in_guest((uintptr_t)ep->ContextRecord->Rip);
		const char *access = ep->ExceptionRecord->ExceptionInformation[0] == 0 ? "read"
		        : ep->ExceptionRecord->ExceptionInformation[0] == 1 ? "write" : "execute";
		mb_diag_banner(guest_code ? "unhandled fault" : "a fault in host code");
		if (guest_code)
			mb_diag("[veh] unhandled fault: addr=%p access=%s rip=%p, %s",
			        (void *)fault, access, (void *)ep->ContextRecord->Rip,
			        owner ? "inside a registered block" : "OUTSIDE every registered block");
		else
			mb_diag("[veh] fault in host code, passed on to the process's exception handlers (it may well be handled):"
			        " addr=%p access=%s rip=%p, %s",
			        (void *)fault, access, (void *)ep->ContextRecord->Rip,
			        owner ? "inside a registered block" : "outside every registered block");
		if (owner) {
			size_t pi = (fault - owner->addr.start) >> MB_PAGESHIFT;
			mb_diag(" (page %zu status=%u dirty=%u invisible=%u)",
			        pi, owner->pages[pi].status, owner->pages[pi].dirty, owner->pages[pi].invisible);
		}
		say_region(fault);
		mb_diag(" [%d block(s) registered]\n", g_nblocks);
		const CONTEXT *c = ep->ContextRecord;
		say_code_and_regs((const unsigned char *)c->Rip, (uintptr_t)c->Rsp, (uintptr_t)c->Rbp,
		                  (uintptr_t)c->Rax, (uintptr_t)c->Rbx, (uintptr_t)c->Rcx, (uintptr_t)c->Rdx,
		                  (uintptr_t)c->Rsi, (uintptr_t)c->Rdi, (uintptr_t)c->R8, (uintptr_t)c->R9,
		                  (uintptr_t)c->R10, (uintptr_t)c->R11, (uintptr_t)c->R12, (uintptr_t)c->R13,
		                  (uintptr_t)c->R14, (uintptr_t)c->R15);
		if (guest_code) say_guest_stack((uintptr_t)c->Rsp);
		const uintptr_t rip = (uintptr_t)c->Rip;
		if (guest_can_die_here(rip)) {
			if (mb_host_guest_death_in_handler(mb_guest_ctx, "the core crashed: it %s address %p (at %p)",
			        write ? "wrote to" : "read or ran", (void *)fault, (void *)rip)) {
				ep->ContextRecord->Rsp = (DWORD64)mb_guest_ctx->esc_rsp;
				ep->ContextRecord->Rip = (DWORD64)(uintptr_t)&mb_guarded_escape;
				report_end(phase_before);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
		report_end(phase_before);
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

static void initialize(void) {
	g_fault_tls = TlsAlloc();
	if (g_fault_tls == TLS_OUT_OF_INDEXES) {
		fprintf(stderr, "miniBox: TlsAlloc failed\n");
		abort();
	}
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
