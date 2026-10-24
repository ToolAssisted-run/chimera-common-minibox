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
#include <unistd.h>
#include <fcntl.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/syscall.h>
#endif

/* The block LIST changes only when a machine is created or destroyed, on the
 * thread that does that, so a plain array serves it. (The Rust reference
 * guards it with a mutex for multi-core hosting.) The per-block TRACKING state
 * the handler writes is another matter: see mb_block_track_lock. */
#define MAX_BLOCKS 64
static mb_block *g_blocks[MAX_BLOCKS];
static int g_nblocks = 0;

/* The trampoline that runs the guest's fault handler for a fault in guest code
 * (guarded.S, Linux) is the guest's too: it runs on the guest's stack with the
 * guest's %fs, and a fault in it is one the guest took. */
static bool in_guest_tramp(uintptr_t rip) {
#ifndef _WIN32
	return rip >= (uintptr_t)&mb_fault_tramp_guest && rip < (uintptr_t)&mb_fault_tramp_guest_end;
#else
	(void)rip;
	return false;
#endif
}

/* Whether an instruction is the guest's own: guest code lives in a registered
 * block, host code never does. */
static bool code_in_guest(uintptr_t rip) {
	for (int i = 0; i < g_nblocks; i++)
		if (mb_range_contains(g_blocks[i]->addr, rip)) return true;
	return in_guest_tramp(rip);
}

/* The context slot of this thread's gs block: the context of the guest the
 * thread is running, and 0 while it runs the host (the interop blob sets it on
 * the way in and clears it on every way out, a system call or a callback
 * included). A Linux thread that never ran a guest has no gs base, and is not
 * read. Safe in a signal handler: one system call and one load. */
static uintptr_t gs_context_slot(void) {
#ifdef _WIN32
	return (uintptr_t)__readgsqword(0x18);   /* the TEB's SubSystemTib */
#else
	uintptr_t base = 0;
	if (syscall(SYS_arch_prctl, 0x1004 /* ARCH_GET_GS */, &base) != 0 || base == 0) return 0;
	return *(volatile const uintptr_t *)(base + 0x18);
#endif
}

/* A fault the guest's own code took, with a machine to charge it to: that is a
 * guest dying, which the host survives (mb_host_guest_death). The guest's own
 * code is either in its memory, or anywhere at all while the thread is inside
 * a guest call: a call through a null or wild function pointer, or to a
 * callback the host never registered, faults at an address outside every
 * block (2026-10-18; it used to be judged the host's, and fatal). Anything
 * else - a fault in host code, or with no machine running - is not, and stays
 * fatal. */
static bool guest_can_die_here(uintptr_t rip) {
	return mb_guest_ctx != NULL && mb_guest_ctx->host_ptr != 0
		&& (code_in_guest(rip) || gs_context_slot() == (uintptr_t)mb_guest_ctx);
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
 * passed on. The shared code below sets the phase on both hosts. On Linux the
 * signal is blocked for the handler's duration and the guest's own handler
 * runs after it, on the faulting thread's stack (send_to_guest), so there a
 * fault inside the handler is always said and fatal.
 *
 * A guest that dies inside its own handler leaves every handler frame at once:
 * control goes to the escape, and the frames below never unwind. Whichever
 * handler sends it there puts this thread's depth and phase back to none
 * (leave_every_handler_frame), and on Linux the signal mask the first fault
 * arrived with, or the next fault on this thread would find itself nested in
 * a handler that is long gone.
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
/* the Windows handler samples no base: ask_guest falls back to thread_area */
static uintptr_t guest_fs_sampled(void) { return 0; }
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
/* the same handler behind a guest-entry thunk: for a fault taken in HOST code */
static mb_guest_fault_fn g_guest_fault_entered;

void mb_tripguard_set_guest_fault_handler(mb_guest_fault_fn fn) { g_guest_fault = fn; }
void mb_tripguard_set_guest_fault_entry(mb_guest_fault_fn fn) { g_guest_fault_entered = fn; }

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
	return in_guest_tramp(rip);
}

/* Testing hook, for hosts that do NOT drop the base: pretend one did, so the
 * repair below is exercised on a machine where the bug cannot happen. */
__attribute__((no_stack_protector))
static bool drop_fs_for_test(void) {
	static int cached = -1;
	if (cached < 0) cached = getenv("MB_DROP_FS_ON_FAULT") ? 1 : 0;
	return cached == 1;
}

/* Is the faulting instruction itself an %fs access? That is a property of
 * the bytes at rip, not of any register - which matters, because the
 * register we would otherwise ask (%fs) is the one under suspicion in here.
 * Legacy prefixes precede any REX, opcode or VEX/EVEX byte, so the first
 * non-legacy byte ends the search. Pure reads, no libc - and no stack
 * protector for the same reason as below. */
__attribute__((no_stack_protector))
static bool insn_has_fs_prefix(uintptr_t rip) {
	const uint8_t *p = (const uint8_t *)rip;
	for (int i = 0; i < 5; i++) {
		uint8_t b = p[i];
		if (b == 0x64) return true;
		if (b == 0x65 || b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2
		    || b == 0xF3 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26)
			continue;
		return false;
	}
	return false;
}

/* Whether the bytes at rip can be read at all: same question as the maps
 * scan, which needs no thread pointer. An unreadable rip is not a repair
 * either way, it is a wild jump, and looking at it must not fault. */
__attribute__((no_stack_protector))
static bool rip_bytes_readable(uintptr_t rip) {
	/* insn_has_fs_prefix reads up to 5 bytes: both pages, when they differ */
	const uintptr_t last = rip + 4;
	return mb_page_readable(rip)
	    && ((last & ~(uintptr_t)MB_PAGEMASK) == (rip & ~(uintptr_t)MB_PAGEMASK) || mb_page_readable(last));
}

/* Leaving a fault handler back into guest code: install the guest's thread
 * pointer, whatever the register happens to hold now. The install comes
 * first, because at_fault may be 0 - a base the OS dropped - under which no
 * libc call survives, including the diagnostic below; the install is what
 * makes the rest safe. Reporting under the installed pointer is fine: it is
 * mapped and stable, which is all fprintf needs. */
__attribute__((no_stack_protector))
static void mb_restore_guest_fs(uintptr_t at_fault) {
	if (drop_fs_for_test()) at_fault = 0;
	mb_wrfsbase(mb_guest_ctx->thread_area);
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
			fprintf(stderr, "miniBox: the OS does not keep the guest %%fs (it is "
			                "lost at a context switch, not at a fault); reinstalling it\n");
			fflush(stderr);
		}
	}
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

#ifdef _WIN32
/* Windows: the vectored handler runs on the faulting thread's own stack, so the
 * guest's handler is called from it directly. (Linux points the thread at a
 * trampoline instead: send_to_guest, below.) */
static bool ask_guest(uintptr_t addr, bool write, bool from_host_code) {
	if (!g_guest_fault || !guest_protected(addr, write)) return false;
	/* A fault in HOST code on a page the guest protected: host C writing guest
	 * memory, inside a system call or a callback the guest made. The thread is
	 * not in the guest then - the interop blob cleared its context slot on the
	 * way out - so the guest's handler, which makes system calls of its own
	 * (Xenia's unprotects the page), arrived at one with no context and the
	 * process died in the blob (chimera issue 280: Max Payne 3 at frame 1247,
	 * Windows, a Vulkan result written into a watched page). That call is
	 * entered the way every call from the host is, through the guest-entry
	 * thunk, which brings the context and the stacks for a call made from
	 * inside a host call, and its %fs. A fault in guest code is already inside
	 * and is called directly, as before. */
	if (from_host_code && g_guest_fault_entered) {
		const int phase = fault_phase();
		fault_phase_set(MB_PHASE_GUEST);
		const bool handled = g_guest_fault_entered((uint64_t)addr, write ? 1 : 0) != 0;
		fault_phase_set(phase);
		return handled;
	}
	/* guest code runs from here: a fault it takes on a held page is served */
	const int phase = fault_phase();
	fault_phase_set(MB_PHASE_GUEST);
	mb_context *const in = mb_guest_ctx;
	if (in) InterlockedIncrement(&in->guest_handlers);
#ifdef MB_HAVE_FSBASE
	/* ...and with the guest's own thread pointer, when it owns %fs. The
	 * handler put the host's back on entry, and guest code under it reads
	 * the HOST's thread locals and arrives at its system calls with a base
	 * the dispatcher refuses ("something outside a fault took it"). Host C
	 * runs again after it, so the host's comes back. */
	const bool swap = mb_fs_swap && mb_guest_ctx && mb_guest_ctx->fs_swap;
	const uintptr_t host_fs = swap ? mb_rdfsbase() : 0;
	/* the very base the guest faulted on, when the handler sampled a live one:
	 * the faulting thread's own, whichever thread that is */
	const uintptr_t sampled = guest_fs_sampled();
	if (swap) mb_wrfsbase(sampled && sampled != mb_early_tp ? sampled : mb_guest_ctx->thread_area);
#endif
	const bool handled = g_guest_fault((uint64_t)addr, write ? 1 : 0) != 0;
#ifdef MB_HAVE_FSBASE
	if (swap) mb_wrfsbase(host_fs);
#endif
	if (in) InterlockedDecrement(&in->guest_handlers);
	fault_phase_set(phase);
	return handled;
}
#endif

/* Shared: handle a write fault at addr. Returns true if handled.
 *
 * Under the block's tracking lock, because what this writes - the epoch's
 * bitmap and count, the unheld bitmap, the dirty map, a snapshot - is shared
 * with every other thread that faults on this block and with the block
 * operations the guest's syscalls run. Two faults on two pages of one bitmap
 * word used to lose one of the two bits (test_tripguard). */
/* set by trip when the OS refused the protection change a write needed: the
 * guest's death then says so instead of "crashed" (one thread runs a guest) */
static volatile bool g_protect_refused;

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
		/* The baseline first, because it can fail: with no memory for the
		 * copy, the write is not let through and the machine stops, where it
		 * used to go ahead with the sealed bytes lost for good - every later
		 * state of that page then had no baseline to be told apart from. */
		if (!mb_page_maybe_snapshot(p, mirror_of(b, page_start))) {
			mb_block_track_unlock(b);
			fault_phase_set(phase);
			mb_diag("miniBox: no memory for the baseline copy of the page at %p; the machine stops rather than lose it\n",
				(void *)page_start);
			return false;
		}
		mb_block_epoch_capture(b, pi, mirror_of(b, page_start));
		/* And a state being taken in the background wants the same bytes: this
		 * is the last moment they exist. One atomic exchange when no state is
		 * being taken, which is almost always. */
		mb_block_plan_capture(b, pi);
		mb_block_note_dirty(b, pi, true);
		mb_range r = { page_start, MB_PAGESIZE };
		if (mb_pal_protect(r, mb_page_native_prot(p)) != 0) {
			/* The OS refused to make the page writable. On Linux that is
			 * nearly always the limit on memory maps (vm.max_map_count, 65530
			 * by default: every page with a protection of its own costs two),
			 * and it used to be a trap with no word at all. Now it is said,
			 * and the write is an unhandled fault: the guest's death, with
			 * this as the reason (2026-10-18). The page stays as it was. */
			mb_block_track_unlock(b);
			fault_phase_set(phase);
			g_protect_refused = true;
			mb_diag("miniBox: the system refused to make the page at %p writable"
			        " (on Linux, usually the limit on memory maps, vm.max_map_count);"
			        " the core's write to it cannot go ahead\n", (void *)page_start);
			return false;
		}
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
#else
	if (!mb_page_readable((uintptr_t)ip) || !mb_page_readable((uintptr_t)ip + 15)) {
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
 * is on, and asks the OS about each page first (VirtualQuery on Windows,
 * /proc/self/maps on Linux) - a nested fault in here would lose the report
 * it is part of. */
#ifdef _WIN32
bool mb_page_readable(uintptr_t p) {
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery((void *)p, &mbi, sizeof mbi) != sizeof mbi) return false;
	if (mbi.State != MEM_COMMIT) return false;
	return (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;
}
#elif defined(__linux__)
/* Raw open/read only: no stdio, no allocation - this runs inside the fault
 * handler (and stdio already bit us once, with RPCS3). A page counts when
 * some mapping covers it with read permission. */
bool mb_page_readable(uintptr_t p) {
	int fd = open("/proc/self/maps", O_RDONLY);
	if (fd < 0) return false;
	char buf[4096];
	size_t have = 0;
	bool found = false, readable = false;
	for (;;) {
		ssize_t n = read(fd, buf + have, sizeof buf - have);
		if (n <= 0) break;
		have += (size_t)n;
		size_t line = 0;
		for (size_t i = 0; i < have; i++) {
			if (buf[i] != '\n') continue;
			/* start-end perms ... : parse only what we need */
			uintptr_t lo = 0, hi = 0;
			size_t j = line;
			while (j < i && buf[j] != '-') { lo = lo * 16 + (uintptr_t)(buf[j] <= '9' ? buf[j] - '0' : (buf[j] & 0xdf) - 'A' + 10); j++; }
			if (j < i && buf[j] == '-') {
				j++;
				while (j < i && buf[j] != ' ') { hi = hi * 16 + (uintptr_t)(buf[j] <= '9' ? buf[j] - '0' : (buf[j] & 0xdf) - 'A' + 10); j++; }
				if (j + 1 < i && p >= lo && p < hi) {
					found = true;
					readable = buf[j + 1] == 'r';
					break;
				}
			}
			line = i + 1;
		}
		if (found) break;
		/* keep an unterminated tail (a split mapping line) for next read */
		if (line > 0) { memmove(buf, buf + line, have - line); have -= line; }
		else if (have == sizeof buf) break;   /* absurdly long line: give up */
	}
	close(fd);
	return found && readable;
}
#else
bool mb_page_readable(uintptr_t p) { (void)p; return true; }
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
		if ((p == rsp || (p & MB_PAGEMASK) == 0) && !mb_page_readable(p)) break;
		const uintptr_t v = *(const uintptr_t *)p;
		if (!mb_range_contains(L->elf, v)) continue;
		mb_diag(" +%llu:%llx", (unsigned long long)(p - rsp), (unsigned long long)v);
		shown++;
	}
	mb_diag(shown ? "\n" : " (nothing on it)\n");
}

/* The same walk, for a death that is not a fault (host.c record_death). */
void mb_tripguard_say_guest_stack(uintptr_t rsp) { say_guest_stack(rsp); }

#ifndef _WIN32
/* ---- Linux: SIGSEGV via sigaction, chaining to the previous handler ---- */
#include <signal.h>
#include <ucontext.h>
#include <sys/mman.h>
static struct sigaction g_old_sa;

static void handler_inner(int sig, siginfo_t *info, void *ucontext);

/* the signal mask the outermost fault on this thread arrived with */
static __thread sigset_t g_entry_mask;

/* Control is going to the escape (a guest that died), which no handler frame
 * below this one will see: the thread is out of every one of them. A death
 * nested in the guest's own handler would otherwise leave the depth and the
 * phase of the frame it abandoned, and sigreturn would install the mask that
 * frame ran with - every signal but the fault signals blocked, for good. */
static void leave_every_handler_frame(ucontext_t *uc) {
	if (g_fault_depth > 0) uc->uc_sigmask = g_entry_mask;
	g_fault_depth = 0;
	g_fault_phase = MB_PHASE_NONE;
}

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
	 * see the Windows handler below, where that is the normal case.
	 * No %fs instruction runs here unless the probe said they exist
	 * (mb_fs_swap): on a host without them this whole block is skipped. */
	const bool guest_rip = mb_fs_swap && mb_guest_ctx
	                       && rip_in_guest((uintptr_t)((ucontext_t *)ucontext)
	                                       ->uc_mcontext.gregs[REG_RIP]);
	/* ...or by the pointer itself, as handler_foreign asks it: code outside
	 * the guest's memory that runs on the guest's %fs - the interop blob's
	 * first push onto a held stack page, a guest's call to a null or wild
	 * address - must not have host C run on it either (2026-10-18). The
	 * guest's pointer is its thread area or the early stand-in, and never the
	 * host's own. */
	const uintptr_t tp_now = mb_fs_swap && mb_guest_ctx ? mb_rdfsbase() : 0;
	const bool guest_tp = !guest_rip && mb_fs_swap && mb_guest_ctx && mb_guest_ctx->fs_swap
	                      && mb_guest_ctx->host_fs && tp_now != mb_guest_ctx->host_fs
	                      && (tp_now == mb_guest_ctx->thread_area || (mb_early_tp && tp_now == mb_early_tp));
	const uintptr_t fs_at_fault = guest_rip ? tp_now : 0;
	if ((guest_rip || guest_tp) && mb_guest_ctx->host_fs) mb_wrfsbase(mb_guest_ctx->host_fs);
	const uintptr_t fault = (uintptr_t)info->si_addr;
	const uintptr_t rip = (uintptr_t)((ucontext_t *)ucontext)->uc_mcontext.gregs[REG_RIP];
	/* A %fs access with the base already lost is the repair, not a fault to
	 * handle: reinstall and resume the instruction, exactly as the Windows
	 * path does. Three facts have to hold together: the base is neither the
	 * live thread pointer nor its musl stand-in, the faulting instruction
	 * actually reads through %fs, and its address belongs to no block - a
	 * dropped base adds its displacement to nothing, so the address is
	 * small or kernel-high, never a guest range. Anything else - including
	 * every trip fault, which must reach trip() below - is normal handling,
	 * not a repair. In particular neither the register nor the parked base
	 * can name the loss on their own: where the OS hands the handler a
	 * valid base anyway, a faulting %fs access reads TEB, and only the
	 * instruction says what it was. A fault that arrives back with %fs
	 * already correct is the guest's own and goes below as it always did -
	 * which is what bounds the retry to one pass. */
	/* What %fs IS for this guest decides what the repair puts back: its own
	 * thread pointer when it owns %fs (fs_swap), and otherwise the host's
	 * base, parked at entry. Not the thread pointer for every guest: on
	 * Linux the host's C runs on %fs - glibc's thread locals, errno, malloc's
	 * cache - and a guest that does not own %fs is not swapped back at the
	 * syscall dispatcher or at an extcall, so a thread pointer installed for
	 * it would have host code reading its thread locals out of the guest's
	 * block until the guarded call returned. The bound is the same value: a
	 * fault that arrives with %fs already what it should be is the guest's
	 * own. (Windows is different: host code never uses FS there, and a guest
	 * that reads %fs without owning it needs its thread pointer - see veh_fs.) */
	const uintptr_t fs_want = !guest_rip ? 0
	                        : mb_guest_ctx->fs_swap ? mb_guest_ctx->thread_area : mb_guest_ctx->host_fs;
	if (guest_rip && fs_at_fault != fs_want
	    && fs_at_fault != mb_early_tp && owner_of(fault) == NULL
	    && rip_bytes_readable(rip) && insn_has_fs_prefix(rip)) {
		if (mb_guest_ctx->fs_swap) {
			mb_restore_guest_fs(fs_at_fault);
		} else {
			/* the host's base is already back in the register (above) */
			static bool said = false;
			if (!said) {
				said = true;
				fprintf(stderr, "miniBox: a guest that does not own %%fs found it lost; the host's base is back\n");
				fflush(stderr);
			}
		}
		return;
	}
	handler_inner(sig, info, ucontext);
	if ((uintptr_t)((ucontext_t *)ucontext)->uc_mcontext.gregs[REG_RIP] == (uintptr_t)&mb_guarded_escape) {
		/* a death: the escape puts the host's base back itself */
		leave_every_handler_frame((ucontext_t *)ucontext);
		return;
	}
	/* Back to the guest's, from the value the entry thunk recorded rather than
	 * from whatever was in the register on the way in. Same value on a host
	 * that preserves the base across a signal, and the right one on a host
	 * that does not. Only for guests that own %fs: the rest keep the host's,
	 * and rewriting it here would trade it for the thread pointer. */
	if (guest_rip && mb_guest_ctx->fs_swap) mb_restore_guest_fs(fs_at_fault);
	else if (guest_tp) mb_wrfsbase(tp_now);
#else
	handler_inner(sig, info, ucontext);
	if ((uintptr_t)((ucontext_t *)ucontext)->uc_mcontext.gregs[REG_RIP] == (uintptr_t)&mb_guarded_escape)
		leave_every_handler_frame((ucontext_t *)ucontext);
#endif
}


/* A fault INSIDE the fault handler, which is how this used to die in silence.
 *
 * sa_mask is sigfillset, so SIGSEGV is blocked while the handler runs (all but
 * the guest's own handler, which ask_guest opens it for); a second one is then
 * force-delivered with the default action and the process is gone
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

/* What the fault trampoline (guarded.S) saves the vector state with: xsave's
 * area for every feature the OS turned on, or fxsave's 512 bytes without it.
 * AMX's tile data is left out of the mask: Linux makes it trap on first use,
 * and code that never asked for it has none to keep. Set at initialize. */
MB_HIDDEN uint64_t mb_xsave_size = 512;
MB_HIDDEN uint64_t mb_xsave_mask = 0;

static void xsave_measure(void) {
	uint32_t a, b, c, d;
	__asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
	if (!(c & (1u << 27))) return;   /* no OSXSAVE: fxsave */
	uint32_t lo, hi;
	__asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
	__asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0xd), "c"(0));
	if (b < 576) return;
	mb_xsave_size = b;   /* every feature in XCR0, AMX's included: enough */
	mb_xsave_mask = (((uint64_t)hi << 32) | lo) & ~((1ull << 17) | (1ull << 18));
}

/* A page the guest may write, as far as its own protection goes: one a frame
 * on a guest thread's stack can be built in (an epoch may hold it; the write
 * then trips as any other). */
static bool guest_writable(uintptr_t addr) {
	mb_block *b = owner_of(addr);
	return b && tracked_status(b->pages[(addr - b->addr.start) >> MB_PAGESHIFT].status);
}

/* A fault on a page the guest protected, for the guest's own handler.
 *
 * Not called from here: this runs on the host's alternate signal stack, one
 * per host thread, and a handler that gives way to another guest thread there
 * (RPCS3's waits for a flush) left its frames on it, under the next fault's
 * (2026-10-18). Instead the interrupted thread is pointed at a trampoline
 * (guarded.S) that runs the handler on the thread's own stack once this has
 * returned, and puts back every register before the instruction is retried.
 * Below the faulting code's red zone; the trampoline's arguments that do not
 * fit in the two registers it is handed go in this thread's gs block.
 *
 * A fault in guest code calls the handler directly, with the guest's %fs (the
 * signal handler puts it back on the way out). A fault in host code - host C
 * writing guest memory in a system call, chimera issue 280 - calls it through
 * the guest-entry thunk, which brings the context, the stacks and the %fs.
 *
 * A handler that answers 0 leaves the address in the gs block, and the retry
 * of the instruction finds it there: an unhandled fault, as with no handler.
 * True when the thread was pointed at the trampoline. */
static bool send_to_guest(ucontext_t *uc, uintptr_t addr, bool write, bool from_host_code) {
	uintptr_t *tib = mb_thread_block();
	const uintptr_t declined = tib[MB_TIB_FAULT_DECLINED];
	tib[MB_TIB_FAULT_DECLINED] = 0;
	if (declined == addr) return false;
	if (!g_guest_fault || !guest_protected(addr, write)) return false;
	const mb_guest_fault_fn fn = from_host_code && g_guest_fault_entered ? g_guest_fault_entered : g_guest_fault;
	const uintptr_t sp = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
	const uintptr_t top = sp - 128;
	/* A guest stack must have room for the trampoline's frame, in pages the
	 * guest may write: a fault on its own guard page (a stack that ran out)
	 * is the guest's death, not a handler call on a stack with no room. */
	if (!from_host_code) {
		const uintptr_t frame = 18 * 8 + (uintptr_t)mb_xsave_size + 64 + 8 + 256;
		for (uintptr_t a = (top - frame) & ~(uintptr_t)MB_PAGEMASK; a < top; a += MB_PAGESIZE)
			if (!guest_writable(a)) return false;
	}
	tib[MB_TIB_FAULT_FN] = (uintptr_t)fn;
	tib[MB_TIB_FAULT_RIP] = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
	tib[MB_TIB_FAULT_RDI] = (uintptr_t)uc->uc_mcontext.gregs[REG_RDI];
	tib[MB_TIB_FAULT_RSI] = (uintptr_t)uc->uc_mcontext.gregs[REG_RSI];
	uc->uc_mcontext.gregs[REG_RSP] = (greg_t)top;
	uc->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)(from_host_code ? &mb_fault_tramp_host : &mb_fault_tramp_guest);
	uc->uc_mcontext.gregs[REG_RDI] = (greg_t)addr;
	uc->uc_mcontext.gregs[REG_RSI] = (greg_t)(write ? 1 : 0);
	return true;
}

static void handler_inner(int sig, siginfo_t *info, void *ucontext) {
	uintptr_t fault = (uintptr_t)info->si_addr;
	ucontext_t *uc = (ucontext_t *)ucontext;
	bool write = (uc->uc_mcontext.gregs[REG_ERR] & 2) != 0;
	/* Nested in the handler: served only in the guest's own handler, whose
	 * faults are guest faults (ask_guest opened the signal for exactly that),
	 * and only so deep. Any other phase cannot get here with the signal
	 * blocked, and is said all the same in case it ever does. */
	if (g_fault_depth > 0 && (g_fault_phase != MB_PHASE_GUEST || g_fault_depth >= MB_FAULT_DEPTH_MOST)) {
		sigsafe_report_nested(fault, (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]);
		signal(SIGSEGV, SIG_DFL);
		return;  /* the instruction runs again and the default action takes it */
	}
	if (g_fault_depth == 0) {
		g_outer_fault = fault;
		g_outer_rip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
		g_entry_mask = uc->uc_sigmask;
	}
	g_fault_depth++;
	trail_add(fault, (uintptr_t)uc->uc_mcontext.gregs[REG_RIP],
	          (uintptr_t)uc->uc_mcontext.gregs[REG_RSP], write ? 1 : 0);
	trail_stage(1);
	bool tripped = write && trip(fault);
	trail_stage(2);
	bool asked = tripped ? false : send_to_guest(uc, fault, write, !rip_in_guest((uintptr_t)uc->uc_mcontext.gregs[REG_RIP]));
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
			const bool halted = rip_bytes_readable(rip) && *(const unsigned char *)rip == 0xf4;
			const bool refused = g_protect_refused;
			g_protect_refused = false;
			const bool escapable = halted
				? mb_host_guest_death_in_handler(mb_guest_ctx,
					"the core stopped itself after finding its own memory corrupt (a halt at %p)", (void *)rip)
				: refused
				? mb_host_guest_death_in_handler(mb_guest_ctx,
					"the system refused a memory protection change the core's write to %p needed"
					" (on Linux, usually vm.max_map_count; at %p)", (void *)fault, (void *)rip)
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
/* The fault handler's own work - a page snapshot, a report naming the code
 * bytes, the registers and the guest's stack - wants more than a runtime's
 * small one: Mono and .NET install 16 KiB, and a report that overruns it ends
 * the process without a word. One smaller than this is replaced (the
 * runtime's memory is its own, and left alone; 2026-10-18). */
#define MB_ALTSTACK_LEAST (256 * 1024)

void mb_tripguard_ensure_altstack(void) {
	stack_t ss_old;
	memset(&ss_old, 0, sizeof ss_old);
	if (sigaltstack(NULL, &ss_old) == 0 && !(ss_old.ss_flags & SS_DISABLE) && ss_old.ss_sp
	    && ss_old.ss_size >= MB_ALTSTACK_LEAST)
		return;  /* this thread already has one big enough */
	if (ss_old.ss_flags & SS_ONSTACK) return;   /* never swapped out from under a handler */
	stack_t ss;
	memset(&ss, 0, sizeof(ss));
	ss.ss_size = 1024 * 1024;  /* the handler's report runs here, fprintf and all */
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
				leave_every_handler_frame(uc);
			return;
		}
	}
	const struct sigaction *old = sig == SIGILL ? &g_old_ill : &g_old_fpe;
	if (old->sa_flags & SA_SIGINFO) old->sa_sigaction(sig, info, ucontext);
	else if (old->sa_handler == SIG_DFL || old->sa_handler == SIG_IGN) signal(sig, SIG_DFL);   /* the instruction runs again and the default takes it */
	else old->sa_handler(sig);
}

/* A stop asked for from another thread (host.c's wbx_stop_guest), delivered
 * by signal to the thread that calls the guest. It ends the call only when
 * that thread is running guest code with no fault being handled - the same
 * place, and the same way, a crash in guest code ends it. Anywhere else it is
 * left for the next system call (host.c) or the next signal. A signal that is
 * not a stop goes to whoever had it before. */
static struct sigaction g_old_stop;
/* No stack protector on this frame either: the check reads %fs:0x28, and the
 * signal can come in while the guest's %fs is in. */
__attribute__((no_stack_protector))
static void handler_stop(int sig, siginfo_t *info, void *ucontext) {
	ucontext_t *uc = (ucontext_t *)ucontext;
	const uintptr_t rip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
#ifdef MB_HAVE_FSBASE
	/* The stop usually comes in while the thread runs guest code, and with a
	 * guest that keeps its own %fs (fs_swap: xemu's does) the guest's thread
	 * pointer is still in. Host C reads its own thread's variables through
	 * %fs - g_fault_depth below, and the C library's in everything the death
	 * path calls - so the host's goes back first, as handler() does, and the
	 * guest's on the way out to the guest. Read through the guest's, the
	 * C library's allocator took the guest's memory for its own, and a stop
	 * of xemu on Linux crashed in realloc instead of stopping (chimera#330).
	 * Only for a guest pointer (the rip in guest code, or one of the guest's
	 * thread pointers): the frontend's own threads get this signal never,
	 * but a stray one is left exactly as it came. */
	const uintptr_t tp_now = mb_fs_swap && mb_guest_ctx ? mb_rdfsbase() : 0;
	const bool guest_tp = mb_fs_swap && mb_guest_ctx && mb_guest_ctx->fs_swap && mb_guest_ctx->host_fs
		&& tp_now != mb_guest_ctx->host_fs
		&& (rip_in_guest(rip) || tp_now == mb_guest_ctx->thread_area || (mb_early_tp && tp_now == mb_early_tp));
	if (guest_tp) mb_wrfsbase(mb_guest_ctx->host_fs);
#else
	const bool guest_tp = false;
	const uintptr_t tp_now = 0;
#endif
	if (mb_guest_ctx != NULL && mb_guest_ctx->stop_pending && g_fault_depth == 0
	    && guest_can_die_here(rip) && mb_stop_due(mb_guest_ctx)) {
#ifdef MB_HAVE_FSBASE
		/* host C from here on, which needs the host's %fs */
		if (mb_guest_ctx->fs_swap && mb_guest_ctx->host_fs) mb_wrfsbase(mb_guest_ctx->host_fs);
#endif
		mb_guest_ctx->stop_pending = 0;
		mb_host_guest_death_in_handler(mb_guest_ctx, "%s", mb_host_stop_reason(mb_guest_ctx));
		uc->uc_mcontext.gregs[REG_RSP] = (greg_t)mb_guest_ctx->esc_rsp;
		uc->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)&mb_guarded_escape;
		leave_every_handler_frame(uc);
		return;
	}
	if (mb_guest_ctx != NULL && mb_guest_ctx->stop_pending) {   /* ours: asked again later */
#ifdef MB_HAVE_FSBASE
		if (guest_tp) mb_wrfsbase(tp_now);
#endif
		return;
	}
	if (g_old_stop.sa_flags & SA_SIGINFO) {
		if (g_old_stop.sa_sigaction) g_old_stop.sa_sigaction(sig, info, ucontext);
	} else if (g_old_stop.sa_handler != SIG_DFL && g_old_stop.sa_handler != SIG_IGN) {
		g_old_stop.sa_handler(sig);
	}
#ifdef MB_HAVE_FSBASE
	if (guest_tp) mb_wrfsbase(tp_now);
#endif
	(void)tp_now;
}

void mb_tripguard_stop_signal_install(void) {
	static int installed;
	if (installed) return;
	installed = 1;
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = handler_stop;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sigaction(MB_STOP_SIGNAL, &sa, &g_old_stop);
}

#ifdef MB_HAVE_FSBASE
/* Every OTHER handler in the process, run under the host's thread pointer.
 *
 * Guest code with thread locals runs with the guest's %fs installed. A signal
 * the host's own runtime sends itself can land there - Mono stops each thread
 * for its garbage collector with one - and its handler, host code, then reads
 * its thread-locals through the guest's pointer and dies: a PCSX2 core,
 * interpreting for seconds at a time, took Chimera down that way at its first
 * collection (mono's suspend_signal_handler, in
 * mono_hazard_pointer_save_for_signal_handler).
 *
 * So the handlers already installed when miniBox starts - the runtime's -
 * are wrapped: on the thread running a guest, with the guest's pointer in,
 * the host's goes in for the handler and whatever was there comes back after.
 * Anywhere else the handler is called as it was. The faults miniBox serves
 * itself (SIGSEGV, SIGBUS, SIGILL, SIGFPE) are not wrapped here: those
 * handlers already know.
 *
 * The wrapped handlers also take SA_ONSTACK, for the same reason miniBox's own
 * do (mb_tripguard_ensure_altstack): without it the kernel puts the handler's
 * frame on the stack the thread is on, which in guest code is the GUEST's -
 * host data written into guest memory, and a frame that reaches a clean
 * (write-protected) tracked page cannot be delivered at all. Mono's suspend
 * handler waits in sigsuspend for the restart signal, and that signal's frame,
 * a page further down the guest's stack, killed Chimera with a kernel SIGSEGV.
 * On a thread with no alternate stack SA_ONSTACK changes nothing. */
static struct sigaction g_foreign[NSIG];

__attribute__((no_stack_protector))
static void handler_foreign(int sig, siginfo_t *info, void *ucontext) {
	const struct sigaction *old = &g_foreign[sig];
	/* No %fs instruction unless the probe said they exist (mb_fs_swap), as in
	 * handler() above. Where the OS keeps rdfsbase from userspace it is an
	 * illegal instruction, and this runs for every wrapped signal on every
	 * thread of the process, guest or not: unguarded it would take the
	 * frontend down at its runtime's first signal. On such a host no guest
	 * ever owns %fs, so there is nothing to put back either. */
	const bool swaps = mb_fs_swap;
	const uintptr_t tp = swaps ? mb_rdfsbase() : 0;
	mb_context *c = mb_guest_ctx;
	/* the guest's pointer is in when this thread was stopped in guest code, or
	 * holds one of the guest's pointers (a transition, between the swap and
	 * the jump) - and is not the host's own */
	const bool guest_tp = swaps && c && c->host_fs && tp != c->host_fs
		&& (rip_in_guest((uintptr_t)((ucontext_t *)ucontext)->uc_mcontext.gregs[REG_RIP])
		    || tp == c->thread_area || (mb_early_tp && tp == mb_early_tp));
	if (guest_tp) mb_wrfsbase(c->host_fs);
	if (old->sa_flags & SA_SIGINFO) old->sa_sigaction(sig, info, ucontext);
	else if (old->sa_handler != SIG_DFL && old->sa_handler != SIG_IGN) old->sa_handler(sig);
	if (guest_tp) mb_wrfsbase(tp);
}

static void wrap_foreign_handlers(void) {
	for (int sig = 1; sig < NSIG; sig++) {
		if (sig == SIGKILL || sig == SIGSTOP || sig == SIGSEGV || sig == SIGBUS
		    || sig == SIGILL || sig == SIGFPE) continue;
		struct sigaction old;
		if (sigaction(sig, NULL, &old) != 0) continue;
		const bool has_handler = (old.sa_flags & SA_SIGINFO)
			? old.sa_sigaction != NULL
			: old.sa_handler != SIG_DFL && old.sa_handler != SIG_IGN;
		if (!has_handler) continue;
		g_foreign[sig] = old;
		struct sigaction sa = old;
		sa.sa_sigaction = handler_foreign;
		sa.sa_flags = old.sa_flags | SA_SIGINFO | SA_ONSTACK;
		if (sigaction(sig, &sa, NULL) != 0) g_foreign[sig].sa_handler = SIG_DFL;
	}
}
#endif

static void initialize(void) {
	trail_open();
	xsave_measure();
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
#ifdef MB_HAVE_FSBASE
	wrap_foreign_handlers();
#endif
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
/* A stop sent to a thread that is inside the host's fault handler: it is
 * pointed here, and the trap it takes ends the call from inside that handler
 * (veh_inner), the way a crash in the guest's own fault handler ends it. */
extern char mb_stop_trap[];
__asm__(".text\n\t.p2align 4\nmb_stop_trap:\n\tud2\n");

/* A stop asked for from another thread (host.c's wbx_stop_guest): the thread
 * that calls the guest is suspended, and when it is running guest code it is
 * sent to the escape - the same way a crash in guest code is (veh_fs below).
 * With no fault of this machine being handled it goes there at once. When the
 * only faults being handled are ones whose guest fault handler is running, it
 * is in that handler's code, called from inside the host's own handler - and
 * a guest that loops in there was never stopped on Windows (chimera#363:
 * RPCS3 waiting in its texture cache for a renderer that waited for it). Then
 * it is sent to a trap, and leaves every handler frame from inside the
 * handler, which also puts this thread's fault depth back to none (veh). Not
 * while the host's own handler code runs, or a fault on another thread is
 * being handled: it is let go, and left for the next system call (host.c) or
 * the next ask. 1 when it was sent. */
int mb_tripguard_stop_thread(void *thread) {
	HANDLE t = (HANDLE)thread;
	if (SuspendThread(t) == (DWORD)-1) return 0;
	CONTEXT c;
	memset(&c, 0, sizeof c);
	c.ContextFlags = CONTEXT_FULL;
	int sent = 0;
	if (GetThreadContext(t, &c) && mb_guest_ctx != NULL && mb_guest_ctx->stop_pending
	    && code_in_guest((uintptr_t)c.Rip)) {
		const long handling = mb_guest_ctx->handling, in_handler = mb_guest_ctx->guest_handlers;
		const bool idle = handling == 0;
		const bool in_own_handler = in_handler > 0 && handling == in_handler;
		if ((idle || in_own_handler) && mb_stop_due(mb_guest_ctx)) {
			mb_guest_ctx->stop_pending = 0;
			mb_host_guest_death_in_handler(mb_guest_ctx, "%s", mb_host_stop_reason(mb_guest_ctx));
			if (idle) {
				c.Rsp = (DWORD64)mb_guest_ctx->esc_rsp;
				c.Rip = (DWORD64)(uintptr_t)&mb_guarded_escape;
			} else {
				c.Rip = (DWORD64)(uintptr_t)mb_stop_trap;
			}
			c.ContextFlags = CONTEXT_CONTROL;
			sent = SetThreadContext(t, &c) != 0;
		}
	}
	ResumeThread(t);
	return sent;
}

__attribute__((no_stack_protector))
static LONG CALLBACK veh(EXCEPTION_POINTERS *ep) {
	const DWORD last_error = GetLastError();
	mb_context *const handled = mb_guest_ctx;
	if (handled) InterlockedIncrement(&handled->handling);
	const LONG r = veh_fs(ep);
	if (handled) InterlockedDecrement(&handled->handling);
	/* a death: out of every handler frame at once (see the phase notes). The
	 * frames left behind are this thread's faults still being handled, each
	 * counted in its depth, and the guest fault handlers they called: none of
	 * them comes back to take itself off the count, or a later stop would
	 * wait for them for ever. */
	if (r == EXCEPTION_CONTINUE_EXECUTION && ep->ContextRecord->Rip == (DWORD64)(uintptr_t)&mb_guarded_escape) {
		if (handled) {
			InterlockedExchangeAdd(&handled->handling, -(long)fault_depth());
			InterlockedExchange(&handled->guest_handlers, 0);
		}
		fault_depth_set(0);
		fault_phase_set(MB_PHASE_NONE);
	}
	SetLastError(last_error);
	return r;
}

__attribute__((no_stack_protector))
static LONG CALLBACK veh_fs(EXCEPTION_POINTERS *ep) {
#ifdef MB_HAVE_FSBASE
	const bool guest_rip = mb_fs_swap && mb_guest_ctx
	                       && rip_in_guest((uintptr_t)ep->ContextRecord->Rip);
	const uintptr_t fs_at_fault = guest_rip ? mb_rdfsbase() : 0;
	const uintptr_t fault = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
	const uintptr_t rip = (uintptr_t)ep->ContextRecord->Rip;
	/* The real register, not drop_fs_for_test's pretend one: that hook forces
	 * the answer unconditionally, and a forced answer here would re-fault into
	 * the same retry for ever. The cost is that this path is exercised on
	 * Windows only, which is also the only place it can happen.
	 * Three facts have to hold together: the base is neither the live thread
	 * pointer nor its musl stand-in, the faulting instruction actually reads
	 * through %fs, and its address belongs to no block - a dropped base adds
	 * its displacement to nothing, so the address is small or kernel-high,
	 * never a guest range. Anything else - including every trip fault, which
	 * must reach veh_inner below - is normal handling, not a repair. In
	 * particular the register alone cannot name the loss: the handler runs
	 * with a valid base of its own here, so a faulting %fs access reads TEB,
	 * and only the instruction says what it was. A fault that arrives back
	 * with %fs already correct is the guest's own and goes below as it
	 * always did - which is what bounds the retry to one pass. */
	if (guest_rip && fs_at_fault != mb_guest_ctx->thread_area
	    && fs_at_fault != mb_early_tp && owner_of(fault) == NULL
	    && rip_bytes_readable(rip) && insn_has_fs_prefix(rip)) {
		mb_restore_guest_fs(fs_at_fault);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	LONG r = veh_inner(ep);
	/* As above, for the fault a handled trip or ask leaves behind: only for
	 * guests that own %fs, whose base this restores. */
	if (guest_rip && mb_guest_ctx->fs_swap && r == EXCEPTION_CONTINUE_EXECUTION)
		mb_restore_guest_fs(fs_at_fault);
	return r;
#else
	return veh_inner(ep);
#endif
}

static LONG CALLBACK veh_inner(EXCEPTION_POINTERS *ep) {
	DWORD code = ep->ExceptionRecord->ExceptionCode;
	/* a stop sent from inside the guest's own fault handler (mb_tripguard_stop_thread):
	 * the death is already recorded */
	if (code == STATUS_ILLEGAL_INSTRUCTION && ep->ContextRecord->Rip == (DWORD64)(uintptr_t)mb_stop_trap
	    && mb_guest_ctx != NULL && mb_guest_ctx->esc_rsp != 0) {
		ep->ContextRecord->Rsp = (DWORD64)mb_guest_ctx->esc_rsp;
		ep->ContextRecord->Rip = (DWORD64)(uintptr_t)&mb_guarded_escape;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
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

/* A page the OS refused to commit (memblock.c, ensure_committed): committed
 * now, before dirty tracking - which would otherwise give an uncommitted page
 * its protection and fault on it for ever. *oom when refused again. */
static bool commit_on_fault(uintptr_t addr, bool write, bool *oom) {
	mb_block *b = owner_of(addr);
	if (!b || mb_block_track_held_here(b)) return false;
	const int phase = fault_phase();
	fault_phase_set(MB_PHASE_TRACK);
	const bool served = mb_block_commit_on_fault(b, addr, write, oom);
	fault_phase_set(phase);
	return served;
}

static LONG veh_access_violation(EXCEPTION_POINTERS *ep, bool write, uintptr_t fault) {
	bool oom = false;
	if (commit_on_fault(fault, write, &oom)) return EXCEPTION_CONTINUE_EXECUTION;
	/* refused again: nothing else can serve a page with no memory behind it -
	 * dirty tracking would protect it and trap on the refusal - so it is
	 * reported, as the host being out of memory */
	if (!oom && write && trip(fault)) return EXCEPTION_CONTINUE_EXECUTION;
	if (!oom && ask_guest(fault, write, !rip_in_guest((uintptr_t)ep->ContextRecord->Rip))) return EXCEPTION_CONTINUE_EXECUTION;

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
		if (oom)
			mb_diag("[veh] out of memory: Windows would not commit the page at %p (error %lu); the machine cannot go on\n",
			        (void *)fault, (unsigned long)GetLastError());
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
		{	/* What the OS thinks of the page that was written to. A fault in
			 * host code is usually somebody else's memory, and "reserved but
			 * not committed", "read-only", or "part of a loaded image" is the
			 * difference between a mapping this library took away and a heap
			 * walking off the end of its own segment. chimera#123 turned on
			 * that one line. */
			MEMORY_BASIC_INFORMATION mbi;
			if (VirtualQuery((void *)fault, &mbi, sizeof mbi))
				mb_diag(" [vq] base=%p alloc=%p size=%llx state=%lx protect=%lx allocprotect=%lx type=%lx\n",
				        mbi.BaseAddress, mbi.AllocationBase, (unsigned long long)mbi.RegionSize,
				        (unsigned long)mbi.State, (unsigned long)mbi.Protect,
				        (unsigned long)mbi.AllocationProtect, (unsigned long)mbi.Type);
			else
				mb_diag(" [vq] VirtualQuery(%p) failed\n", (void *)fault);
		}
		const CONTEXT *c = ep->ContextRecord;
		say_code_and_regs((const unsigned char *)c->Rip, (uintptr_t)c->Rsp, (uintptr_t)c->Rbp,
		                  (uintptr_t)c->Rax, (uintptr_t)c->Rbx, (uintptr_t)c->Rcx, (uintptr_t)c->Rdx,
		                  (uintptr_t)c->Rsi, (uintptr_t)c->Rdi, (uintptr_t)c->R8, (uintptr_t)c->R9,
		                  (uintptr_t)c->R10, (uintptr_t)c->R11, (uintptr_t)c->R12, (uintptr_t)c->R13,
		                  (uintptr_t)c->R14, (uintptr_t)c->R15);
		if (guest_code) say_guest_stack((uintptr_t)c->Rsp);
		const uintptr_t rip = (uintptr_t)c->Rip;
		if (guest_can_die_here(rip)) {
			const bool died = oom
				? mb_host_guest_death_in_handler(mb_guest_ctx, "the computer is out of memory: Windows would not give the core "
				      "the memory it needs (at %p). Close other programs, or give the greenzone less memory, and go back to a safe frame",
				      (void *)fault)
				: mb_host_guest_death_in_handler(mb_guest_ctx, "the core crashed: it %s address %p (at %p)",
				      write ? "wrote to" : "read or ran", (void *)fault, (void *)rip);
			if (died) {
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
