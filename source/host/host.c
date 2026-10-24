/* WaterboxHost: ties the memory block, ELF loader, VFS, and context together;
 * dispatches guest syscalls; seals; saves/loads top-level state. Faithful C
 * port of BizHawk waterboxhost src/host.rs (Linux single-thread subset). */
#define _GNU_SOURCE
#include "minibox_internal.h"
#include "minibox_threads.h"
#include "minibox.h"
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
#ifndef _WIN32
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/uio.h>
/* the spin sampler's host, and the lock that lets mb_host_destroy wait for it
 * (see sample_fn) */
static pthread_mutex_t sample_lock = PTHREAD_MUTEX_INITIALIZER;
static struct mb_host *sample_h;
#endif

struct mb_host {
	/* wbx_stop_from_here / wbx_stop_guest: the thread that calls the guest,
	 * and why a stop was asked for */
	char stop_why[200];
	bool have_stop_thread;
#ifdef _WIN32
	void *stop_thread;   /* a HANDLE that may suspend and redirect it */
	unsigned long stop_thread_id;
#else
	pthread_t stop_thread;
#endif
	/* GuestFaultHandler, raw and through its thunk: looked up once, on the
	 * first activate (a strcmp over every export, twice, on every state call) */
	uintptr_t fault_raw, fault_entry;
	bool fault_known;
	mb_fs *fs;
	uintptr_t program_break;
	mb_elf *elf;
	mb_layout layout;
	mb_block *block;
	bool active, sealed;
	mb_context context;
	mb_thunks *thunks;
	mb_threads *threads;
	uint64_t getrandom_state; /* deterministic entropy stream, per host */
	uint64_t clock_start_ns;  /* the second the machine's clock starts at, in ns (wbx_set_clock_start) */
	uint32_t kit_revision;    /* the guest kit the core was built with (__wbx_kit_revision; 0 before) */
	/* what the machine's small non-memory state was when the epoch began, so a
	 * REVERSE delta can put it back. The memory half lives in the block. */
	uintptr_t epoch_brk;
	uint8_t *epoch_threads;
	size_t epoch_threads_len;
	/* everything a planned state carries except the pages: written when the
	 * state is asked for, because it describes that moment (mb_host_state_size) */
	uint8_t *plan_head; size_t plan_head_len;
	uint8_t *plan_tail; size_t plan_tail_len;
	/* why the guest died, for wbx_get_death; meaningful while context.dead */
	char death[512];
	/* where the output of the call that last wrote any begins (context.calls,
	 * and the output count then): the dying call's own words */
	uint64_t out_call, out_mark;
};

/* ---- syscall numbers (x86-64) ---- */
enum {
	NR_read=0, NR_write=1, NR_open=2, NR_close=3, NR_dup=32, NR_stat=4, NR_fstat=5, NR_lseek=8,
	NR_mmap=9, NR_mprotect=10, NR_munmap=11, NR_brk=12, NR_rt_sigaction=13, NR_rt_sigprocmask=14,
	NR_ioctl=16, NR_readv=19, NR_writev=20, NR_sched_yield=24, NR_mremap=25, NR_madvise=28,
	NR_nanosleep=35, NR_getpid=39, NR_exit=60, NR_truncate=76, NR_ftruncate=77,
	NR_getppid=110, NR_gettid=186, NR_futex=202, NR_sched_setaffinity=203, NR_sched_getaffinity=204, NR_pread64=17, NR_pwrite64=18, NR_socket=41, NR_sysinfo=99, NR_prctl=157, NR_openat=257, NR_newfstatat=262, NR_set_thread_area=205, NR_clock_nanosleep=230,
	NR_clock_gettime=228, NR_set_tid_address=218, NR_getrandom=318, NR_fcntl=72,
	NR_fsync=74, NR_fdatasync=75, NR_sync=162, NR_syncfs=306,
	NR_getuid=102, NR_getgid=104, NR_geteuid=107, NR_getegid=108, NR_wbx_clone=2000,
	NR_getrusage=98,
	NR_tkill=200, NR_exit_group=231, NR_tgkill=234,
	NR_readlink=89, NR_readlinkat=267, NR_pipe=22, NR_pipe2=293,
};


#define MAP_ANONYMOUS 0x20
#define MAP_STACK 0x20000
#define MAP_FIXED 0x10
#define MAP_FIXED_NOREPLACE 0x100000
#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED 2
#define O_TRUNC 01000
#define MADV_DONTNEED 4
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_REQUEUE 3
#define FUTEX_LOCK_PI 6
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10
#define FUTEX_CLOCK_REALTIME 256
#define FUTEX_UNLOCK_PI 7

static uintptr_t serr(int e) { return (uintptr_t)(intptr_t)(-mb_linux_errno(e)); }  /* -errno as usize, in Linux numbers */
static uintptr_t sok(mb_sword v) { return (uintptr_t)v; }

/* open, and openat(AT_FDCWD), which is the same call: libcs use one or the
 * other, so the rules must not depend on which. v3 O_TRUNC needs write access
 * (else EACCES), and after a successful open the file is truncated, except
 * streams (truncate refuses those with EBADF, which is ignored). openat used
 * to skip the v3 half. */
static uintptr_t open_file(mb_host *h, const char *p, int flags) {
	if (mb_threads_spec(h->threads) == 3 && (flags & O_TRUNC) != 0 && (flags & 3) == 0) return serr(EACCES);
	mb_sword r = mb_fs_open(h->fs, p, flags);
	if (r < 0) return serr((int)-r);
	if (mb_threads_spec(h->threads) == 3 && (flags & O_TRUNC) != 0) {
		mb_sword t = mb_fs_truncate_fd(h->fs, (int)r, 0);
		if (t < 0 && t != -EBADF) return serr((int)-t);
	}
	return sok(r);
}

static mb_prot arg_to_prot(uintptr_t a, bool *bad) {
	*bad = false;
	if (a & ~(uintptr_t)(PROT_READ|PROT_WRITE|PROT_EXEC)) { *bad = true; return MB_PROT_NONE; }
	if (a & PROT_EXEC) return (a & PROT_WRITE) ? MB_PROT_RWX : MB_PROT_RX;
	if (a & PROT_WRITE) return MB_PROT_RW;
	if (a & PROT_READ) return MB_PROT_R;
	return MB_PROT_NONE;
}

/* The guest syscall dispatcher (sysv64; installed in the Context). */
/* Called BY the interop blob, so it is sysv64 even on a Windows host. */
/* Set MINIBOX_TRACE_SYSCALLS=1 to log every guest syscall as it happens. The
 * guest is a sandbox: when it dies there is no core dump to read and no debugger
 * attached, so the last logged syscall is usually the whole diagnosis. Flushed
 * per line, because whatever kills the process will not flush for us. */
static int trace_syscalls(void) {
	static int on = -1;
	if (on < 0) { const char *e = getenv("MINIBOX_TRACE_SYSCALLS"); on = e && *e && *e != '0'; }
	return on;
}

/* A pointer the guest handed over, checked before the host follows it.
 *
 * Nothing here used to check. A guest that called open(NULL) - and mia does,
 * hunting for a database it has not got - made the host dereference address
 * zero inside libc, and the process died with no diagnostic at all: the sandbox
 * killed by the thing it is supposed to contain. A guest may be broken, may be
 * hostile, and may be neither and simply have a bug; none of those may take the
 * host down.
 *
 * The whole arena is one range, so "is this the guest's" is one comparison. */
static bool guest_owns(mb_host *h, uintptr_t addr, uintptr_t len)
{
	if (addr == 0 || len == 0) return false;
	mb_range all = mb_layout_all(&h->layout);
	if (addr < all.start || addr >= mb_range_end(all)) return false;
	return len <= mb_range_end(all) - addr;
}

/* Whether host code may read (write false) or write the guest's bytes over
 * [addr, addr+len): guest_owns says the range is the guest's address space,
 * and this also asks the pages - a freed or no-access page there faults in
 * HOST code, which ended the process (2026-10-18). A page the guest protected
 * itself is fine when it exports GuestFaultHandler: the host's fault is passed
 * to it (chimera issue 280). Linux answers EFAULT, and so does every caller. */
static bool guest_can(mb_host *h, uintptr_t addr, uintptr_t len, bool write)
{
	if (len == 0) return true;
	return guest_owns(h, addr, len) && mb_block_host_can(h->block, addr, len, write, h->fault_raw != 0);
}

/* The same question for a host outside miniBox: Chimera's GPU bridge, before
 * it reads a buffer the core hands GL or writes a readback into its memory. */
bool mb_host_guest_can(mb_host *h, uintptr_t addr, uintptr_t len, bool write)
{
	return guest_can(h, addr, len, write);
}

/* The bytes for reading only, through the mirror: see mb_block_read_view */
const void *mb_host_read_view(mb_host *h, uintptr_t addr, uintptr_t len)
{
	if (!guest_owns(h, addr, len)) return NULL;
	return mb_block_read_view(h->block, addr, len);
}

/* A NUL-terminated string in guest memory, or NULL. The scan stops at the end
 * of the arena, so an unterminated string cannot walk the host off the end. */
static const char *guest_str(mb_host *h, uintptr_t addr)
{
	if (!guest_owns(h, addr, 1)) return NULL;
	uintptr_t end = mb_range_end(mb_layout_all(&h->layout));
	for (uintptr_t p = addr; p < end; p++) {
		/* each page asked before its first byte is read (guest_can) */
		if ((p == addr || (p & MB_PAGEMASK) == 0) && !guest_can(h, p, 1, false)) return NULL;
		if (*(const char *)p == 0) return (const char *)addr;
	}
	return NULL;
}

static uintptr_t MB_SYSV dispatch_inner(uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
                          uintptr_t a5, uintptr_t a6, uintptr_t nr, void *hp);

/* ---- a guest that cannot go on ----
 *
 * A guest dies in ways that are nothing to do with the host: it aborts (a Rust
 * panic, a failed allocation, an assertion), it finds its own heap corrupt and
 * halts, it follows a wild pointer, it exits, it asks for a syscall nobody
 * provides. Each of those used to be a trap, and the trap took the frontend
 * with it - the session, what was not saved, and the chance to say why.
 *
 * Now the machine is marked dead and the call that was running returns to the
 * host (guarded.S). Nothing of the guest runs again until a state is loaded,
 * which is a machine that did exist - so the frontend can show why, keep its
 * work, and carry on from its history. Only a death outside a call the host
 * made (the guest's _start, a seal) still traps: there is nothing to go back
 * to. And a fault in HOST code is not a guest's death at all; it stays fatal. */

/* The newest few lines the dying call wrote, joined: usually the reason in the
 * guest's own words. Only this call's - a line from frames ago is not why this
 * one died. A Rust panic ends with a "note:" about backtraces, which is not
 * the reason either. */
static void guest_last_words(mb_host *h, char *out, size_t cap) {
	out[0] = '\0';
	if (h == NULL || h->fs == NULL || cap < 4) return;
	if (h->out_call != h->context.calls) return;   /* it said nothing this call */
	static char tail[4096];
	const size_t n = mb_fs_sysout_since(h->fs, h->out_mark, tail, sizeof tail);
	const char *lines[3]; size_t lens[3]; int count = 0;
	size_t end = n;
	while (end > 0 && count < 3) {
		while (end > 0 && (tail[end - 1] == '\n' || tail[end - 1] == '\r')) end--;
		size_t start = end;
		while (start > 0 && tail[start - 1] != '\n') start--;
		if (end > start && !(end - start >= 5 && memcmp(tail + start, "note:", 5) == 0)) {
			lines[count] = tail + start; lens[count] = end - start; count++;
		}
		end = start;
	}
	size_t o = 0;
	for (int i = count - 1; i >= 0 && o + 1 < cap; i--) {
		if (o != 0) { if (o + 4 >= cap) break; memcpy(out + o, " | ", 3); o += 3; }
		size_t take = lens[i] < cap - 1 - o ? lens[i] : cap - 1 - o;
		memcpy(out + o, lines[i], take); o += take;
	}
	out[o] = '\0';
}

/* Says it, keeps it, marks it. True when a guarded call is in progress to go
 * back to. */
static bool record_death(mb_context *c, bool say_stack, const char *fmt, va_list ap) {
	mb_host *h = c != NULL ? (mb_host *)c->host_ptr : NULL;
	char what[256];
	vsnprintf(what, sizeof what, fmt, ap);
	mb_diag_banner("the guest died");
	mb_diag("miniBox: %s\n", what);
	if (h != NULL) {
		mb_host_diag_guest_output(h);
		char words[300];
		guest_last_words(h, words, sizeof words);
		if (words[0] != '\0') snprintf(h->death, sizeof h->death, "%s. It said: %s", what, words);
		else snprintf(h->death, sizeof h->death, "%s", what);
	}
	if (c == NULL) return false;
	c->dead = 1;
	/* Where the guest was, for a death that is not a fault - an abort, an
	 * exit, a deadlock, all of which arrive through a syscall, so the saved
	 * guest rsp is the one the call left. A fault's report already carries its
	 * own walk, from the faulting rsp (tripguard.c). The same filtered form:
	 * only words inside the ELF, ready for addr2line, because this is the file
	 * people attach to an issue. */
	if (say_stack) {
		mb_diag(" active tid=%u", h && h->threads ? mb_threads_active_tid(h->threads) : 0);
		mb_tripguard_say_guest_stack(c->guest_rsp);
	}
	const bool escapable = c->esc_rsp != 0;
	mb_diag(escapable
		? "  the call returns to the host, and the machine runs nothing until a state is loaded\n"
		: "  not inside a call the host made, so there is nothing to return to\n");
	return escapable;
}

void mb_host_guest_death(mb_context *c, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	const bool escapable = record_death(c, true, fmt, ap);
	va_end(ap);
	if (escapable) mb_guarded_escape_now(c);
	__builtin_trap();
}

bool mb_host_guest_death_in_handler(mb_context *c, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	const bool escapable = record_death(c, false, fmt, ap);
	va_end(ap);
	return escapable;
}

const char *mb_host_stop_reason(const mb_context *c) {
	const mb_host *h = c != NULL ? (const mb_host *)c->host_ptr : NULL;
	return h != NULL && h->stop_why[0] ? h->stop_why : "the host stopped the core";
}

/* ---- a guest that does not come back (2026-10-19) ----
 *
 * A guest that loops forever inside one call froze the frontend: nothing could
 * stop it from another thread. Now the frontend says which thread makes its
 * calls (wbx_stop_from_here), and a watchdog of its own may ask for a stop
 * (wbx_stop_guest): the guest dies at its next system call, in host code, or
 * at once while it runs its own code - interrupted by a signal on Linux,
 * suspended and sent to the escape on Windows - exactly as a crash in guest
 * code ends it. Not while it is in host code (a system call, a callback, a
 * driver): that is left to finish, and the watchdog asks again. A stop the
 * guest works past - a system call of the working kind, or work the frontend
 * counts for it (wbx_count_work_from), a driver call that took long and came
 * back - is dropped (mb_stop_due). */
void mb_host_stop_from_here(mb_host *h) {
#ifdef _WIN32
	HANDLE self = NULL;
	if (h->have_stop_thread) CloseHandle((HANDLE)h->stop_thread);
	h->have_stop_thread = DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &self,
	                                      THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, 0) != 0;
	h->stop_thread = self;
	h->stop_thread_id = GetCurrentThreadId();
#else
	mb_tripguard_stop_signal_install();
	h->stop_thread = pthread_self();
	h->have_stop_thread = true;
#endif
}

int mb_host_stop(mb_host *h, const char *why) {
	if (!h->have_stop_thread || h->context.esc_rsp == 0 || h->context.dead) return 0;
	/* the reason is written once per stop: a second ask must not rewrite it
	 * while the guest's thread may be reading it */
	if (!__atomic_load_n(&h->context.stop_pending, __ATOMIC_ACQUIRE)) {
		snprintf(h->stop_why, sizeof h->stop_why, "%s", why != NULL && why[0] ? why : "the host stopped the core");
		__atomic_store_n(&h->context.stop_activity, mb_work(&h->context), __ATOMIC_RELAXED);
		__atomic_store_n(&h->context.stop_pending, 1, __ATOMIC_RELEASE);
	}
	/* asked on the thread running the call (from a host callback): it is in
	 * host code, so the stop waits for the next system call. Suspending
	 * itself would never come back. */
#ifdef _WIN32
	if (h->stop_thread_id == GetCurrentThreadId()) return 0;
	return mb_tripguard_stop_thread(h->stop_thread);
#else
	if (pthread_equal(h->stop_thread, pthread_self())) return 0;
	return pthread_kill(h->stop_thread, MB_STOP_SIGNAL) == 0;
#endif
}

void mb_host_stop_cancel(mb_host *h) { __atomic_store_n(&h->context.stop_pending, 0, __ATOMIC_RELEASE); }

uint64_t mb_host_activity(mb_host *h) { return mb_work(&h->context); }

void mb_host_count_work_from(mb_host *h, const uint64_t *counter) { h->context.extra_work = counter; }

bool mb_host_death(mb_host *h, char *out, size_t cap) {
	const bool dead = h->context.dead != 0;
	if (out != NULL && cap != 0) {
		const char *src = dead ? h->death : "";
		size_t n = strlen(src);
		if (n >= cap) n = cap - 1;
		memcpy(out, src, n);
		out[n] = '\0';
	}
	return dead;
}

/* Tracing wrapper: the arguments go out BEFORE the syscall runs (a crash
 * inside it still shows what was asked), the result right after - a call
 * that fails where it succeeds elsewhere is exactly what a trace diff is
 * for, and the result column is where that shows. */
static uintptr_t MB_SYSV dispatch(uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
                          uintptr_t a5, uintptr_t a6, uintptr_t nr, void *hp) {
	/* Host C counts on the direction flag being clear (memcpy, memset), and
	 * a guest that called in with it set handed that over (analysis of
	 * 2026-10-18). Before anything else, so nothing runs backwards. */
	__asm__ volatile("cld" ::: "memory");
#ifdef MB_HAVE_FSBASE
	/* The guest trapped in here with %fs = its own thread pointer (a Rust guest
	 * uses %fs-direct TLS), but everything below is host C and glibc - malloc
	 * and fprintf read the host's TLS through %fs. Put the host's back for the
	 * body, and the guest's back before returning to guest code. thread_area is
	 * 0 only during early _start, when the guest is still on %gs and keeping
	 * host %fs is the right answer. */
	mb_host *hfs = (mb_host *)hp;
	const bool swap_fs = hfs->context.fs_swap; /* plain load: NO call may precede the swap */
	/* Inline asm, not a call, so it is allowed to precede the swap: what %fs
	 * held when the guest trapped in here. It should be the guest's thread
	 * pointer; anything else means something between the last boundary and this
	 * one took it away, and the audit below names the syscall we arrived on. */
	const uintptr_t fs_on_entry = swap_fs ? mb_rdfsbase() : 0;
	const uintptr_t ta_on_entry = hfs->context.thread_area;
	if (swap_fs) mb_wrfsbase(hfs->context.host_fs);
#endif
	/* the guest's floating-point control words kept, the host's for the body
	 * (see mb_context): inline asm, nothing called before it */
	mb_context *fpu_ctx = &((mb_host *)hp)->context;
	mb_fpu_get(&fpu_ctx->guest_fcw, &fpu_ctx->guest_mxcsr);
	mb_fpu_set(&fpu_ctx->host_fcw, &fpu_ctx->host_mxcsr);
	uintptr_t res;
	if (!trace_syscalls()) {
		res = dispatch_inner(a1, a2, a3, a4, a5, a6, nr, hp);
	} else {
		fprintf(stderr, "[syscall] %llu (%llx, %llx, %llx)", (unsigned long long)nr,
		        (unsigned long long)a1, (unsigned long long)a2, (unsigned long long)a3);
		fflush(stderr);
		res = dispatch_inner(a1, a2, a3, a4, a5, a6, nr, hp);
		intptr_t s = (intptr_t)res;
		if (s < 0 && s > -4096) fprintf(stderr, " -> ERR %lld\n", (long long)s);
		else fprintf(stderr, " -> %llx\n", (unsigned long long)res);
		fflush(stderr);
	}
#ifdef MB_HAVE_FSBASE
	/* Said once, from host %fs (fprintf needs it on Linux). The guest reaches
	 * this boundary constantly, so a loss anywhere in guest code is named
	 * within microseconds of happening rather than at the eventual crash. */
	if (swap_fs && fs_on_entry != ta_on_entry && fs_on_entry != mb_early_tp) {
		static bool reported = false;
		if (!reported) {
			reported = true;
			fprintf(stderr, "miniBox: guest %%fs was %p, expected %p, on arrival at "
			                "syscall %llu - something outside a fault took it\n",
			        (void *)fs_on_entry, (void *)ta_on_entry, (unsigned long long)nr);
			fflush(stderr);
		}
	}
	if (swap_fs) mb_wrfsbase(hfs->context.thread_area);
#endif
	/* the guest's back: whichever guest thread runs on from here, they share
	 * one set, as every other register this boundary does not swap */
	mb_fpu_set(&fpu_ctx->guest_fcw, &fpu_ctx->guest_mxcsr);
	return res;
}

/* Who asked for it.
 *
 * A guest handed NULL by a refused allocation does not die there. It dies
 * later and somewhere else entirely - a std::map insert, a recompiler
 * dispatch, a settings write - each reading through a null pointer, with
 * nothing left to say which allocation had failed. The syscall boundary is the
 * last place that still knows, so a refusal, or a request large enough to be a
 * mistake in itself, prints the return addresses sitting on the guest's stack.
 *
 * They are guest text addresses, and a core package ships its core.wbx
 * unstripped: addr2line -f -C -e core.wbx <addr> names them.
 *
 * Only what is safe to read: the scan starts at the guest rsp the interop blob
 * parked on the way in and stops at the end of whichever guest stack that rsp
 * is on, so it never walks off into a guard page. */
static void diag_guest_callers(mb_host *h) {
	const uintptr_t rsp = h->context.guest_rsp;
	if (rsp == 0) return;
	mb_range stack;
	if (mb_range_contains(h->layout.main_thread, rsp))     stack = h->layout.main_thread;
	else if (mb_range_contains(h->layout.alt_thread, rsp)) stack = h->layout.alt_thread;
	else return;

	uintptr_t stop = rsp + MB_PAGESIZE * 8;
	if (stop > mb_range_end(stack)) stop = mb_range_end(stack);

	mb_diag("[mmap]   guest callers:");
	int shown = 0;
	for (uintptr_t p = rsp; p + sizeof(uintptr_t) <= stop && shown < 12; p += sizeof(uintptr_t)) {
		const uintptr_t v = *(const uintptr_t *)p;
		if (mb_range_contains(h->layout.elf, v)) {
			mb_diag(" %llx", (unsigned long long)v);
			shown++;
		}
	}
	mb_diag(shown ? "\n" : " (none on the stack)\n");
	mb_diag("[mmap]   addr2line -f -C -e core.wbx <addr> names these\n");
}

/* After a write: if it reached stdout or stderr and is the first this call made,
 * this call's words start where the output stood before it. */
static void note_output(mb_host *h, uint64_t before) {
	if (mb_fs_sysout_total(h->fs) == before || h->out_call == h->context.calls) return;
	h->out_call = h->context.calls;
	h->out_mark = before;
}

static uintptr_t MB_SYSV dispatch_inner(uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
                          uintptr_t a5, uintptr_t a6, uintptr_t nr, void *hp) {
	mb_host *h = (mb_host *)hp;
	(void)a6;
	/* Already dead - it died in a call made from inside a host callback, and the
	 * guest that made the callback carried on regardless. It runs nothing more. */
	if (h->context.dead && h->context.esc_rsp != 0) mb_guarded_escape_now(&h->context);
	switch (nr) {
		case NR_sched_yield: case NR_clock_gettime: case NR_nanosleep: case NR_clock_nanosleep:
		case NR_futex: case NR_gettid: case NR_getpid: break;
		default: __atomic_add_fetch(&h->context.activity, 1, __ATOMIC_RELAXED); break;
	}
	/* A stop asked for from another thread (wbx_stop_guest): a guest that
	 * makes system calls stops at the next one, here in host code - unless it
	 * worked since the ask (this call may be the work). */
	if (mb_stop_due(&h->context)) {
		h->context.stop_pending = 0;
		mb_host_guest_death(&h->context, "%s", h->stop_why);
	}
	switch (nr) {
		case NR_mmap: {
			bool bad; mb_prot prot = arg_to_prot(a3, &bad); if (bad) return serr(EINVAL);
			uintptr_t flags = a4;
			if (!(flags & MAP_ANONYMOUS)) return serr(EOPNOTSUPP);
			if (flags & 0xf00) return serr(EOPNOTSUPP);
			if (flags & MAP_STACK) { if (prot == MB_PROT_RW) prot = MB_PROT_RWSTACK; else return serr(EINVAL); }
			bool no_replace = (flags & MAP_FIXED_NOREPLACE) != 0;
			/* the kernel rounds an unaligned length up to a page; so do we */
			mb_range r = { a1, (a2 + 0xFFF) & ~(uintptr_t)0xFFF };
			/* v3: a bare hint is honoured when those pages are Free, and the
			 * call is placed best-fit otherwise (v2 keeps mapping it fixed).
			 * MAP_FIXED is not a hint: it maps at the address, discarding
			 * overlap, in both versions. MAP_FIXED_NOREPLACE keeps today's
			 * rule in both. */
			if (mb_threads_spec(h->threads) == 3 && a1 != 0 && !no_replace && (flags & MAP_FIXED) == 0 && !mb_block_range_is_free(h->block, r)) r.start = 0;
			/* v3: MAP_FIXED over allocated pages hands them back zero-filled, as
			 * Linux does (a runtime that decommits and recommits with MAP_FIXED
			 * relies on it); v2 keeps their bytes. */
			mb_sword res = mb_block_mmap(h->block, r, prot, h->layout.mmap_arena, no_replace,
			                             mb_threads_spec(h->threads) == 3);
			/* A request bigger than the whole arena is not a tight fit, it is a
			 * mistake - a corrupted size, or a reservation nobody sized against
			 * this machine. Either way the guest is about to be handed NULL and
			 * to die somewhere unrelated, so say who asked while that is still
			 * knowable. mb_block_mmap has already said what the arena looked
			 * like; this adds the caller. */
			if (res < 0 && r.size > h->layout.mmap_arena.size) diag_guest_callers(h);
			return res < 0 ? serr((int)-res) : sok(res);
		}
		case NR_mremap: {
			mb_range r = { a1, a2 };
			/* v3: moves only with MREMAP_MAYMOVE (without it, EEXIST as in
			 * v2); MAYMOVE|FIXED is EINVAL. v2 never examines the flags. */
			mb_sword res;
			if (mb_threads_spec(h->threads) == 3) {
				if ((a4 & MREMAP_FIXED) != 0) return serr(EINVAL);
				res = mb_block_mremap_maymove(h->block, r, a3, h->layout.mmap_arena, (a4 & MREMAP_MAYMOVE) != 0);
			} else res = mb_block_mremap(h->block, r, a3, h->layout.mmap_arena);
			return res < 0 ? serr((int)-res) : sok(res);
		}
		/* mprotect, munmap and madvise round an unaligned length up to a page,
		 * as the kernel does and as mmap here always has; they refused it
		 * (analysis of 2026-10-18). A length that would wrap is EINVAL. */
		case NR_mprotect: {
			bool bad; mb_prot prot = arg_to_prot(a3, &bad); if (bad) return serr(EINVAL);
			if (a2 > UINTPTR_MAX - 0xFFF) return serr(EINVAL);
			mb_range r = { a1, (a2 + 0xFFF) & ~(uintptr_t)0xFFF };
			int res = mb_block_mprotect(h->block, r, prot);
			return res ? serr(-res) : sok(0);
		}
		case NR_munmap: {
			if (a2 > UINTPTR_MAX - 0xFFF) return serr(EINVAL);
			mb_range r = { a1, (a2 + 0xFFF) & ~(uintptr_t)0xFFF };
			/* a thread freeing the stack it is standing on: hold it until it exits */
			if (mb_threads_hold_stack_unmap(h->threads, r)) return sok(0);
			int res = mb_block_munmap(h->block, r); return res ? serr(-res) : sok(0);
		}
		case NR_madvise:
			if (a3 == MADV_DONTNEED) { if (a2 > UINTPTR_MAX - 0xFFF) return serr(EINVAL);
				mb_range r = { a1, (a2 + 0xFFF) & ~(uintptr_t)0xFFF }; int res = mb_block_madvise_dontneed(h->block, r); return res ? serr(-res) : sok(0); }
			return sok(0);
		case NR_brk: {
			mb_range arena = h->layout.sbrk; uintptr_t old = h->program_break, res;
			if (a1 != mb_align_down(a1)) res = old;
			else if (a1 < arena.start) res = old;
			else if (a1 > mb_range_end(arena)) { fprintf(stderr, "miniBox: sbrk heap exhausted\n"); res = old; }
			else if (a1 > old) { mb_range r = { old, a1 - old }; mb_block_mmap_fixed(h->block, r, MB_PROT_RW, true); res = a1; }
			else res = old;
			h->program_break = res; return sok((mb_sword)res);
		}
		case NR_stat:  { const char *p = guest_str(h, a1); if (!p || !guest_can(h, a2, 144, true)) return serr(EFAULT);
		                 mb_sword r = mb_fs_stat_name(h->fs, p, (void *)a2); return r < 0 ? serr((int)-r) : sok(0); }
		case NR_fstat: { if (!guest_can(h, a2, 144, true)) return serr(EFAULT);
		                 mb_sword r = mb_fs_stat_fd(h->fs, (int)a1, (void *)a2); return r < 0 ? serr((int)-r) : sok(0); }
		case NR_ioctl: {
			/* No devices, so nothing is a terminal; but a core asks, and each
			 * answer it reads is written, so that it does not read whatever was
			 * on its stack (analysis of 2026-10-18). The window size is zero by
			 * zero, termios all zeros, and nothing is waiting to be read. Any
			 * other request is answered "done", as it always was. */
			const uintptr_t req = a2 & 0xFFFFFFFFu;
			const uintptr_t out = req == 0x5413 ? 8 /* TIOCGWINSZ */ : req == 0x5401 ? 36 /* TCGETS */
				: req == 0x541B ? 4 /* FIONREAD */ : 0;
			if (out != 0) {
				if (!guest_can(h, a3, out, true)) return serr(EFAULT);
				memset((void *)a3, 0, out);
			}
			return sok(0);
		}
		/* No pipes in-guest (musl's posix_spawn, backing system(),
		 * needs pipe2 and fails here; without an in-guest provider
		 * this stays unreachable).
		 * A caller that needs one must cope with ENOSYS. */
		case NR_pipe: case NR_pipe2: return serr(ENOSYS);
		case NR_read:  { if (!guest_can(h, a2, mb_fs_read_avail(h->fs, (int)a1, a3), true)) return serr(EFAULT);
		                 mb_sword r = mb_fs_read(h->fs, (int)a1, (uint8_t *)a2, a3); return r < 0 ? serr((int)-r) : sok(r); }
		case NR_write: {
			if (!guest_can(h, a2, a3, false)) return serr(EFAULT);
			const uint64_t before = mb_fs_sysout_total(h->fs);
			mb_sword r = mb_fs_write(h->fs, (int)a1, (const uint8_t *)a2, a3);
			note_output(h, before);
			return r < 0 ? serr((int)-r) : sok(r);
		}
		case NR_readv: case NR_writev: {
			/* iovec: {void* base; size_t len} */
			struct iov { uintptr_t base; uintptr_t len; } *iov = (struct iov *)a2;
			if (a3 > 1024) return serr(EINVAL);                       /* IOV_MAX */
			if (!guest_can(h, a2, a3 * sizeof *iov, false)) return serr(EFAULT);
			mb_sword total = 0;
			const uint64_t before = mb_fs_sysout_total(h->fs);
			for (uintptr_t i = 0; i < a3; i++) {
				if (!iov[i].base) continue;
				const uintptr_t want = nr == NR_readv ? mb_fs_read_avail(h->fs, (int)a1, iov[i].len) : iov[i].len;
				if (!guest_can(h, iov[i].base, want, nr == NR_readv)) { note_output(h, before); return total ? sok(total) : serr(EFAULT); }
				mb_sword r = (nr == NR_readv)
					? mb_fs_read(h->fs, (int)a1, (uint8_t *)iov[i].base, iov[i].len)
					: mb_fs_write(h->fs, (int)a1, (const uint8_t *)iov[i].base, iov[i].len);
				if (r < 0) { note_output(h, before); return serr((int)-r); }
				total += r;
			}
			note_output(h, before);
			return sok(total);
		}
		case NR_open:  { const char *p = guest_str(h, a1); if (!p) return serr(EFAULT);
		                 return open_file(h, p, (int)a2); }
		case NR_sysinfo: {
			/* fixed, plausible, deterministic: 1GB total, half free, no swap.
			 * (struct sysinfo is 112 bytes of longs; fill what matters.) */
			if (!guest_can(h, a1, 112, true)) return serr(EFAULT);
			uint64_t *si = (uint64_t *)a1;
			memset(si, 0, 112);
			si[0] = 0;                    /* uptime */
			si[4] = 1024ull << 20;        /* totalram */
			si[5] = 512ull << 20;         /* freeram */
			/* mem_unit is at offset 104. It was written at 100, the top half
			 * of freehigh, so a core read a unit of 0 and 4 GiB of free high
			 * memory. A core built with guest kit revision 1 or later is told
			 * the truth; one built before keeps the old answer, so its movies
			 * replay (MACHINE-SPEC, "Guest kit revisions"). */
			((uint32_t *)a1)[(h->kit_revision >= 1 ? 104 : 100) / 4] = 1;
			return sok(0);
		}
		case NR_getrusage: {
			/* zeros: no resource usage is observable in-guest.
			 * (a1 is who=RUSAGE_SELF/CHILDREN, a2 is struct rusage*.)
			 * A pointer the guest does not own is EFAULT, as on Linux -
			 * not a host fault. */
			if (!guest_can(h, a2, 144, true)) return serr(EFAULT);
			memset((void *)a2, 0, 144);
			return sok(0);
		}
		case NR_prctl:
			/* PR_SET_NAME: a label, not a behavior - accepted and ignored */
			return (int)a1 == 15 ? sok(0) : serr(EINVAL);
		case NR_pread64: {
			/* read at an offset, position untouched. Guest threads cannot
			 * interleave inside one host syscall, so save/seek/read/restore
			 * is atomic as far as any guest can observe. */
			mb_sword pos = mb_fs_seek(h->fs, (int)a1, 0, 1 /* SEEK_CUR */);
			if (pos < 0) return serr((int)-pos);
			mb_sword r = mb_fs_seek(h->fs, (int)a1, (mb_sword)a4, 0 /* SEEK_SET */);
			if (r < 0) return serr((int)-r);
			if (!guest_can(h, a2, mb_fs_read_avail(h->fs, (int)a1, a3), true)) {
				mb_fs_seek(h->fs, (int)a1, pos, 0);
				return serr(EFAULT);
			}
			mb_sword n = mb_fs_read(h->fs, (int)a1, (void *)a2, a3);
			mb_fs_seek(h->fs, (int)a1, pos, 0);
			return n < 0 ? serr((int)-n) : sok(n);
		}
		case NR_socket: {
			/* There is no network in the box, and there is not going to be: the
			 * answer is the one a machine with no such address family gives. It
			 * used to be the end of the guest - which an arcade game checking
			 * for its cabinet's camera found out (chimera issue #184) - and an
			 * emulator that merely probes for a network should be told there is
			 * none, not stopped. Said once in the diagnostics, so a game that
			 * misbehaves for want of one can be traced to it. */
			static bool said;
			if (!said) {
				said = true;
				mb_diag_banner("no network");
				mb_diag("[socket] the core asked for a socket (family %d, type %d); there is no network in the sandbox, and the call was refused (EAFNOSUPPORT). Said once.\n",
				        (int)a1, (int)a2);
			}
			return serr(EAFNOSUPPORT);
		}
		case NR_pwrite64: {
			/* write at an offset, position untouched: pread64's twin. It was
			 * not here, and a call that is not here ends the guest - so a
			 * program that wrote through a descriptor it had failed to open,
			 * which is EBADF and a logged error on any other system, died of
			 * it (chimera issue #185). A buffer the guest does not own is
			 * EFAULT, not a host fault. */
			if (!guest_can(h, a2, a3, false)) return serr(EFAULT);
			mb_sword n = mb_fs_pwrite(h->fs, (int)a1, (const uint8_t *)a2, a3, (mb_sword)a4);
			return n < 0 ? serr((int)-n) : sok(n);
		}
		case NR_openat: {
			/* only the openat that IS open: std::filesystem and newer libcs
			 * reach the flat namespace through AT_FDCWD; a real dirfd has no
			 * meaning here. */
			if ((int)a1 != -100) return serr(EBADF);
			const char *p = guest_str(h, a2); if (!p) return serr(EFAULT);
			return open_file(h, p, (int)a3);
		}
		case NR_newfstatat: {
			if ((int)a1 != -100) return serr(EBADF);
			const char *p = guest_str(h, a2); if (!p || !guest_can(h, a3, 144, true)) return serr(EFAULT);
			mb_sword r = mb_fs_stat_name(h->fs, p, (void *)a3);
			return r < 0 ? serr((int)-r) : sok(0);
		}
		case NR_readlink: case NR_readlinkat: {
			/* Nothing in this box is a symlink, and there is no /proc: the guest
			 * namespace is flat, and every name in it was mounted by the host.
			 *
			 * RPCS3 asks anyway - readlink("/proc/self/exe", ..., PATH_MAX), once
			 * in fs::get_executable_path and once while the overlay hunts for the
			 * icons it draws - and until this arm existed the PS3 core stopped
			 * dead there, "system call 89, which the sandbox does not provide",
			 * before it had drawn a frame. Both call sites guard the result and
			 * carry on without it: the overlay skips the icons it would have
			 * loaded from disk, the path lookup returns an empty string and says
			 * so. That is the branch every non-Linux build already takes.
			 *
			 * So the answer is a refusal, and not a path. A real executable path
			 * would put the host's install directory inside the machine and make
			 * what it does depend on where Chimera was unpacked - the reason
			 * getuid below answers with one fixed identity. A made-up one would
			 * send the guest hunting under a directory that cannot exist. Linux
			 * answers EINVAL when a name is there and is not a link, and ENOENT
			 * when it is not there; so does this. */
			if (nr == NR_readlinkat && (int)a1 != -100) return serr(EBADF);
			const uintptr_t pa  = nr == NR_readlink ? a1 : a2;
			const uintptr_t buf = nr == NR_readlink ? a2 : a3;
			const uintptr_t len = nr == NR_readlink ? a3 : a4;
			const char *p = guest_str(h, pa); if (!p) return serr(EFAULT);
			if (len && !guest_owns(h, buf, 1)) return serr(EFAULT);
			return mb_fs_exists(h->fs, p) ? serr(EINVAL) : serr(ENOENT);
		}
		case NR_close: { mb_sword r = mb_fs_close(h->fs, (int)a1); return r < 0 ? serr((int)-r) : sok(0); }
		case NR_dup:   { mb_sword r = mb_fs_dup(h->fs, (int)a1); return r < 0 ? serr((int)-r) : sok(r); }
		case NR_lseek: { mb_sword r = mb_fs_seek(h->fs, (int)a1, (mb_sword)a2, (int)a3); return r < 0 ? serr((int)-r) : sok(r); }
		case NR_truncate:  { const char *p = guest_str(h, a1); if (!p) return serr(EFAULT);
		                     mb_sword r = mb_fs_truncate_name(h->fs, p, (mb_sword)a2); return r < 0 ? serr((int)-r) : sok(0); }
		case NR_ftruncate: { mb_sword r = mb_fs_truncate_fd(h->fs, (int)a1, (mb_sword)a2); return r < 0 ? serr((int)-r) : sok(0); }
		case NR_clock_gettime: {
			if (!guest_can(h, a2, 16, true)) return serr(EFAULT);
			int64_t *ts = (int64_t *)a2;  /* {tv_sec, tv_nsec} */
			/* v3: the clock starts at the v2 constant and every read ticks
			 * 1 us, then yields (a spinner on the clock hands the others a
			 * chance to run; single-threaded the yield is a no-op) */
			if (mb_threads_spec(h->threads) == 3) {
				mb_threads_advance(h->threads, MB_V3_TICK_NS);
				uint64_t now = h->clock_start_ns + mb_threads_clock_ns(h->threads);
				ts[0] = (int64_t)(now / 1000000000ull); ts[1] = (int64_t)(now % 1000000000ull);
				return mb_threads_yield_value(h->threads, &h->context, sok(0));
			}
			ts[0] = (int64_t)(h->clock_start_ns / 1000000000ull); ts[1] = (int64_t)(h->clock_start_ns % 1000000000ull); return sok(0);
		}
		case NR_getrandom: {
			/* Determinism is the whole contract, so randomness cannot be real:
			 * fill the buffer from a fixed-seed splitmix64. std seeds every
			 * HashMap's RandomState through this call, so a guest that uses a
			 * hash map (every Rust guest does) needs it, and needs it the same
			 * every run. The stream is per-host, starts the same with every
			 * host, and is saved in states (OpenFileTable1, 2026-10-18). */
			if (!guest_can(h, a1, a2, true)) return serr(EFAULT);
			uint8_t *buf = (uint8_t *)a1;
			uint64_t n = a2;
			for (uint64_t i = 0; i < n; i += 8) {
				h->getrandom_state += 0x9E3779B97F4A7C15ull;
				uint64_t z = h->getrandom_state;
				z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
				z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
				z = z ^ (z >> 31);
				uint64_t take = n - i < 8 ? n - i : 8;
				memcpy(buf + i, &z, take);
			}
			return sok((mb_sword)n);
		}
		case NR_fcntl: {
			/* Only the descriptor-flag commands, and only nominally: there is no
			 * exec in a sandbox, so close-on-exec means nothing, and the VFS has
			 * no non-blocking mode to set. Rust's File::open sets FD_CLOEXEC on
			 * every handle it opens, which is how this first came up. */
			switch ((int)a2) {
				case 1: /* F_GETFD */ case 3: /* F_GETFL */ return sok(0);
				case 2: /* F_SETFD */ case 4: /* F_SETFL */ return sok(0);
				default: return serr(EINVAL);
			}
		}
		case NR_sync:
			/* Nothing to flush: the machine's files live in host memory. RPCS3's
			 * save-data path calls sync() after writing a save (cellSaveData, the
			 * non-Windows branch), so until this was answered every PS3 game died
			 * the first time it saved - Dark Souls at "Making SAVE DATA", with
			 * "unimplemented syscall 162" (chimera issue #75). sync(2) cannot fail. */
			return sok(0);
		case NR_fsync: case NR_fdatasync: case NR_syncfs:
			/* the same, for one descriptor: it is flushed if it is open at all */
			{ mb_sword r = mb_fs_sync_fd(h->fs, (int)a1); return r < 0 ? serr((int)-r) : sok(0); }
		case NR_rt_sigaction: {
			/* No signal delivery in-guest: an install is accepted and never
			 * fires. (a1 sig, a2 act, a3 oldact, a4 sigsetsize.) The old
			 * action is reported as the default - SIG_DFL, no flags, empty
			 * mask - because that is what nothing installed means, and a
			 * guest that saves and restores the old action must not read
			 * whatever was on its stack. The kernel's struct is 32 bytes:
			 * handler, flags, restorer, mask. */
			if (a2 != 0 && !guest_can(h, a2, 32, false)) return serr(EFAULT);
			if (a3 != 0) {
				if (!guest_can(h, a3, 32, true)) return serr(EFAULT);
				memset((void *)a3, 0, 32);
			}
			return sok(0);
		}
		case NR_rt_sigprocmask: {
			/* Nothing is delivered, so nothing is blocked: the old mask is
			 * written as empty, not left as what was on the stack. (a1 how,
			 * a2 set, a3 oldset, a4 sigsetsize; the kernel's is 8 bytes.) */
			if (a4 > 128) return serr(EINVAL);
			if (a2 != 0 && !guest_can(h, a2, a4, false)) return serr(EFAULT);
			if (a3 != 0) {
				if (!guest_can(h, a3, a4, true)) return serr(EFAULT);
				memset((void *)a3, 0, a4);
			}
			return sok(0);
		}
		case NR_tkill: case NR_tgkill: {
			/* A signal to one of its own threads. The one a guest sends is to itself:
			 * musl's abort() is tkill(self, SIGABRT), which is how a Rust panic, a
			 * failed allocation and a failed assertion all end (chimera issue #43
			 * met it as "unimplemented syscall 200"). Signal 0 asks whether a thread
			 * exists, and is answered. Any other cannot be delivered - a guest has no
			 * signal handlers here - and would have ended a Linux process, so it ends
			 * the machine the same way. */
			const uintptr_t tid = nr == NR_tkill ? a1 : a2;
			const uintptr_t sig = nr == NR_tkill ? a2 : a3;
			if (sig == 0) return mb_threads_has_thread(h->threads, (uint32_t)tid) ? sok(0) : serr(ESRCH);
			if (sig == 6) mb_host_guest_death(&h->context, "the core aborted");
			mb_host_guest_death(&h->context, "the core raised signal %llu against itself", (unsigned long long)sig);
		}
		case NR_exit_group:
			mb_host_guest_death(&h->context, "the core exited (status %lld)", (long long)(intptr_t)a1);
		case NR_set_thread_area: return serr(ENOSYS);   /* musl handles in userspace */
		/* The address is written (with 0) when the thread exits; one the host
		 * may not write is not kept, as Linux ignores a write there that fails. */
		case NR_set_tid_address: return sok(mb_threads_set_tid_address(h->threads, guest_can(h, a1, 4, true) ? a1 : 0));
		case NR_gettid: return sok(mb_threads_get_tid(h->threads));
		case NR_getpid: case NR_getppid: return sok(1);
		/* One fixed identity. Mesa asks (its option parsing takes the
		 * secure_getenv path, which compares euid with uid), and a core that
		 * answered with the host's real ids would let the machine's behaviour
		 * depend on who ran it. euid == uid, so nothing is treated as
		 * privileged and no path is taken for one user and not another. */
		case NR_getuid: case NR_geteuid: return sok(1000);
		case NR_getgid: case NR_getegid: return sok(1000);
		case NR_sched_yield: return mb_threads_sched_yield(h->threads, &h->context);
		case NR_nanosleep: {
			/* v3: the clock advances by exactly the requested duration, then
			 * one yield. (Negative or out-of-range requests are EINVAL, and a
			 * bad pointer EFAULT, as on Linux.) */
			if (mb_threads_spec(h->threads) != 3) return mb_threads_yield(h->threads, &h->context);
			const int64_t *req = (const int64_t *)a1;
			if (!guest_can(h, a1, 16, false)) return serr(EFAULT);
			if (req[0] < 0 || req[1] < 0 || req[1] >= 1000000000ll) return serr(EINVAL);
			mb_threads_advance(h->threads, mb_threads_ns_of(h->threads, req[0], req[1]));
			return mb_threads_yield(h->threads, &h->context);
		}
		case NR_clock_nanosleep: {
			/* v3: relative requests behave as nanosleep; TIMER_ABSTIME (flag
			 * 1) advances to the absolute target when it is ahead of now, else
			 * nothing. rem is zeroed (nothing interrupts a sleep here). */
			if (mb_threads_spec(h->threads) != 3) return mb_threads_yield(h->threads, &h->context);
			const int64_t *req = (const int64_t *)a3;
			if (!guest_can(h, a3, 16, false)) return serr(EFAULT);
			if (req[0] < 0 || req[1] < 0 || req[1] >= 1000000000ll) return serr(EINVAL);
			uint64_t target = mb_threads_ns_of(h->threads, req[0], req[1]);
			if ((a2 & 1) != 0) {
				/* absolute, on the clock's own scale: convert past the base */
				uint64_t rel = (target > h->clock_start_ns) ? target - h->clock_start_ns : 0;
				uint64_t now = mb_threads_clock_ns(h->threads);
				if (rel > now) mb_threads_advance(h->threads, rel - now);
			} else mb_threads_advance(h->threads, target);
			if (a4) {
				if (!guest_can(h, a4, 16, true)) return serr(EFAULT);
				*(int64_t *)a4 = 0; *((int64_t *)a4 + 1) = 0;
			}
			return mb_threads_yield(h->threads, &h->context);
		}
		case NR_wbx_clone: {
			/* args: (tls/thread_area, child_rsp, child_rip, child_tid, parent_tid*):
			 * the musl pthread struct is read (14 words), the child's first frame
			 * and the parent's tid written */
			if (a1 == 0) return serr(EINVAL);   /* a foreign convention: mb_threads_spawn says why */
			if (!guest_can(h, a1, 14 * 8, false)) return serr(EFAULT);
			if (!guest_can(h, a2 - 16, 16, true) || !guest_can(h, a5, 4, true)) return serr(EFAULT);
			mb_sword r = mb_threads_spawn(h->threads, h->block, a1, a2, a3, a4, (uint32_t *)a5);
			return r < 0 ? serr((int)-r) : sok(r);
		}
		case NR_sched_setaffinity:
			/* Taken and ignored. Guest threads are green threads sharing one host
			 * thread, so there is nothing here to pin - and the affinity of the
			 * thread they actually run on belongs to the host, not to them.
			 *
			 * Mesa is what brought this here: it reads the mask above, gets the
			 * honest "one CPU", and then asks to be pinned to it during thread
			 * setup. Refusing by not implementing it is not a refusal, it is an
			 * abort - the guest dies mid-frame with "unimplemented syscall 203"
			 * and every test in a core that links Mesa fails at once. Saying yes
			 * costs nothing and changes nothing the guest can observe: the mask
			 * it reads back is the same one CPU either way. */
			return sok(0);
		case NR_sched_getaffinity: {
			/* one CPU, honestly: pools and hardware_concurrency stay deterministic.
			 * musl's sysconf(_SC_NPROCESSORS_*) issues this syscall directly, so a
			 * libc-level shadow cannot answer it. Returns the kernel's cpumask
			 * size in bytes, like Linux. */
			if (a3 == 0 || a2 < 8) return serr(EINVAL);
			if (a2 > 4096) a2 = 4096;   /* the answer is 8 bytes; no kernel mask is bigger */
			if (!guest_can(h, a3, a2, true)) return serr(EFAULT);
			memset((void *)a3, 0, a2);
			*(uint8_t *)a3 = 1;
			return sok(8);
		}
		case NR_exit: {
			/* take it BEFORE the thread is gone, do it AFTER it has been swapped
			 * off that stack - by which point another thread is running */
			mb_range held; const bool has_held = mb_threads_take_held_unmap(h->threads, &held);
			const uintptr_t r = mb_threads_exit(h->threads, &h->context);
			if (has_held) mb_block_munmap(h->block, held);
			return r;
		}
		case NR_futex: {
			/* CLOCK_REALTIME only picks which clock a timeout is against, and a
			 * timeout is not honoured here at all (see the bitset ops below). */
			int op = (int)a2 & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
			bool v3 = mb_threads_spec(h->threads) == 3;
			/* v3 timed waits: WAIT's timeout is relative, WAIT_BITSET's
			 * absolute (a guest timespec; NULL waits forever as in v2).
			 * Invalid values are EINVAL, a bad pointer EFAULT, as on Linux. */
			/* the futex word itself is read by the waits and written by the PI
			 * pair; the wakes and requeue only use its address */
			if ((op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET) && !guest_can(h, a1, 4, false)) return serr(EFAULT);
			if ((op == FUTEX_LOCK_PI || op == FUTEX_UNLOCK_PI) && !guest_can(h, a1, 4, true)) return serr(EFAULT);
			if (v3 && (op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET) && a4 != 0) {
				const int64_t *to = (const int64_t *)a4;
				if (!guest_can(h, a4, 16, false)) return serr(EFAULT);
				if (to[0] < 0 || to[1] < 0 || to[1] >= 1000000000ll) return serr(EINVAL);
				uint64_t t = mb_threads_ns_of(h->threads, to[0], to[1]);
				uint64_t dl;
				if (op == FUTEX_WAIT) dl = mb_threads_ns_add(h->threads, mb_threads_clock_ns(h->threads), t);
				else dl = (t > h->clock_start_ns) ? t - h->clock_start_ns : 0;   /* absolute, past the start; at-or-before the start is already due */
				return mb_threads_futex_wait_timeout(h->threads, &h->context, a1, (uint32_t)a3, true, dl);
			}
			switch (op) {
				case FUTEX_WAIT: return mb_threads_futex_wait(h->threads, &h->context, a1, (uint32_t)a3);
				/* v3: a wake yields after waking (the woken thread is runnable
				 * and the waker hands the others a chance to run); the count
				 * is this thread's return when it resumes */
				case FUTEX_WAKE: {
					mb_sword n = mb_threads_futex_wake(h->threads, a1, (uint32_t)a3);
					if (v3) return mb_threads_yield_value(h->threads, &h->context, sok(n));
					return sok(n);
				}
				/* The bitset pair is the plain pair with a mask and an ABSOLUTE
				 * timeout. Rust's std reaches for these - its Mutex, Condvar and
				 * thread::park all wait this way - so a guest built from it spun
				 * on ENOSYS forever: 53.8 million refused calls in 90 seconds, and
				 * not one frame drawn.
				 *
				 * The mask is FUTEX_BITSET_MATCH_ANY in practice, and where it is
				 * not, waking a waiter that did not match is a spurious wake -
				 * which every futex user must already tolerate, because it
				 * re-checks its own condition on waking. So: match any.
				 *
				 * The timeout is ignored, exactly as FUTEX_WAIT's relative one
				 * already is. A waiter here is woken by another guest thread or
				 * not at all; there is no clock in the box to expire against. */
				case FUTEX_WAIT_BITSET: return mb_threads_futex_wait(h->threads, &h->context, a1, (uint32_t)a3);
				case FUTEX_WAKE_BITSET: {
					mb_sword n = mb_threads_futex_wake(h->threads, a1, (uint32_t)a3);
					if (v3) return mb_threads_yield_value(h->threads, &h->context, sok(n));
					return sok(n);
				}
				case FUTEX_REQUEUE: return sok(mb_threads_futex_requeue(h->threads, a1, a5, (uint32_t)a3, (uint32_t)a4));
				case FUTEX_LOCK_PI: return mb_threads_futex_lock_pi(h->threads, &h->context, a1);
				case FUTEX_UNLOCK_PI: return mb_threads_futex_unlock_pi(h->threads, &h->context, a1);
				default: return serr(ENOSYS);
			}
		}
		default:
			/* Something the host does not provide. Answering ENOSYS would send the
			 * guest down a path nobody has looked at, so the rule is still to stop
			 * and say what was asked - stopping the machine, not the process. */
			mb_host_guest_death(&h->context,
			        "the core asked for system call %llu (%llx, %llx, %llx), which the sandbox does not provide",
			        (unsigned long long)nr, (unsigned long long)a1,
			        (unsigned long long)a2, (unsigned long long)a3);
			return serr(ENOSYS);
	}
}

/* ---- lifecycle ---- */

/* A 0-argument entry (_start, co_clean, ecl_seal) through the same guarded
 * call an export takes, so that a guest that dies in its start-up code or
 * its seal ends the machine and not the host (2026-10-18; mb_call_guest_simple
 * had no escape record, and such a death trapped). True when the guest is
 * still alive afterwards. */
static bool call_guest_guarded(mb_host *h, uintptr_t entry) {
	const uintptr_t thunk = mb_thunks_get(h->thunks, entry, &h->context);
	if (thunk == 0) mb_call_guest_simple(entry, &h->context);   /* a full pool: as before */
	/* Called as a plain function on both systems: the thunk takes no argument,
	 * and mb_guarded_call keeps every register a win64 caller expects kept
	 * (rdi, rsi and xmm6-15 too). Declared sysv on Windows, the call made
	 * MinGW's GCC 13 fail (an internal compiler error in choose_baseaddr). */
	else ((uintptr_t (*)(void))thunk)();
	return !h->context.dead;
}

static bool run_proc_if_present(mb_host *h, const char *name) {
	uintptr_t p = mb_elf_proc_addr(h->elf, name);
	return p ? call_guest_guarded(h, p) : true;
}

/* What a callback slot the host never registered answers: the guest's death,
 * said as such. It used to be address 0, and the call faulted outside the
 * guest, which the host could not tell from its own crash (2026-10-18). */
static uintptr_t MB_SYSV unregistered_callback(void) {
	mb_host_guest_death(mb_guest_ctx, "the core called a host callback that was never registered");
	return 0;
}

/* mb_host_new's way out, from any point: everything it built, given back in
 * one place, so a field added to mb_host later cannot be leaked by one refusal
 * and freed by another. The fault handler is told first: it was pointed at
 * this host's layout early, and a refusal that left it there sent the next
 * fault into freed memory (the case chimera#127 fixed in mb_host_destroy). */
static mb_host *host_new_unwind(mb_host *h) {
	mb_tripguard_forget_layout(&h->layout);
	/* a guest that died while starting was the one the handlers judged by */
	if (mb_guest_ctx == &h->context) mb_guest_ctx = NULL;
	if (h->block) { mb_block_deactivate(h->block); mb_block_free(h->block); }
	mb_fs_free(h->fs);
	mb_elf_free(h->elf); mb_thunks_free(h->thunks); mb_threads_free(h->threads);
	free(h);
	return NULL;
}

mb_host *mb_host_new(const uint8_t *image, size_t image_len, const char *module_name,
                     const mb_memory_layout_template *tpl, char *errbuf, size_t errlen) {
	/* (the image is the caller's: nothing here keeps a copy of it - one used
	 * to be kept for the whole session and never read, 100 to 330 MB on the
	 * big cores) */
	if (!mb_elf_check(image, image_len, errbuf, errlen)) return NULL;
	mb_host *h = (mb_host *)calloc(1, sizeof(mb_host));
	h->thunks = mb_thunks_new();
	h->threads = mb_threads_new();

	/* build the layout: elf span (page-expanded), then the fixed + sized areas */
	mb_range elf = mb_range_align_expand(mb_elf_span(image, image_len));
	mb_layout *L = &h->layout;
	uintptr_t end = mb_range_end(elf);
	#define ADD(field, sz) do { L->field.start = end; L->field.size = mb_align_up(sz); end = mb_range_end(L->field); } while (0)
	L->elf = elf;
	ADD(main_thread, 1u << 20); ADD(alt_thread, 1u << 20);
	ADD(sbrk, tpl->sbrk_size); ADD(sealed, tpl->sealed_size); ADD(invis, tpl->invis_size);
	ADD(plain, tpl->plain_size); ADD(mmap_arena, tpl->mmap_size);
	#undef ADD
	mb_range all = mb_layout_all(L);
	/* Spec v2: the block may span any number of 4 GiB regions (a PS3 core keeps
	 * a flat 4 GiB guest view plus an 8 GiB dispatch table); only the start
	 * stays 4 GiB aligned. */
	if (all.start & 0xffffffffu) {
		snprintf(errbuf, errlen, "HostMemoryLayout must start on a 4GiB boundary");
		return host_new_unwind(h);
	}

	mb_tripguard_set_layout(&h->layout);
	h->block = mb_block_new(all);
	if (!h->block) { snprintf(errbuf, errlen, "failed to create memory block"); return host_new_unwind(h); }
	h->program_break = L->sbrk.start;
	h->fs = mb_fs_new();
	mb_context_init(&h->context, L->main_thread.start + L->main_thread.size,
	                L->alt_thread.start + L->alt_thread.size, dispatch);

	mb_prepare_thread();
	h->context.host_ptr = (uintptr_t)h;
	mb_block_activate(h->block);
	h->active = true;

	if (mb_elf_load(image, image_len, module_name, L, h->block, &h->elf) != 0) {
		snprintf(errbuf, errlen, "failed to load guest ELF");
		return host_new_unwind(h);
	}

	/* Decided before the guest runs a single instruction: a guest carrying
	 * PT_TLS uses %fs-relative thread locals (Rust) and needs the host to hand
	 * it its own %fs; every C/C++ guest on the waterbox musl uses %gs and is
	 * left exactly as it was. */
#ifdef MB_HAVE_FSBASE
	/* Eager, not lazy: the global probe result gates the entry park and the
	 * fault repair for EVERY guest, and C's && would otherwise never run it
	 * for a guest with no PT_TLS - leaving the gates at their zero value
	 * while the instructions would have worked. */
	{ const bool fs_ok = mb_fsbase_ok();
	  h->context.fs_swap = mb_elf_has_tls(h->elf) && fs_ok && !getenv("MB_NO_FS_SWAP"); }
	/* Said once, unprompted, because it decides whether a guest carrying its own
	 * thread locals can work at all - and when it is wrong the failure is a
	 * crash with nothing to connect it to. A guest with no TLS says nothing. */
	if (mb_elf_has_tls(h->elf)) {
		fprintf(stderr, "miniBox: guest declares TLS; %%fs swap %s%s\n",
		        h->context.fs_swap ? "ON" : "OFF",
		        h->context.fs_swap ? ""
		            : (getenv("MB_NO_FS_SWAP") ? " (MB_NO_FS_SWAP set)"
		                                       : " (the OS does not offer fsbase to user mode)"));
		fflush(stderr);
	}
#endif

	/* Machine-spec version, decided before the guest runs a single
	 * instruction: a guest declares v3 by exporting a uint32_t
	 * __wbx_machine_spec holding 3 (read the way __wbxsysinfo is; host VA ==
	 * guest VA). No symbol, or a 2, is v2: every v2 behaviour bit for bit.
	 * Anything else refuses the load - a movie recorded under version N
	 * requires a host implementing version N. */
	{ uintptr_t spec_addr = mb_elf_proc_addr(h->elf, "__wbx_machine_spec");
	  int spec = 2;
	  if (spec_addr) {
		if (!guest_owns(h, spec_addr, 4)) { snprintf(errbuf, errlen, "guest's __wbx_machine_spec points outside its memory"); return host_new_unwind(h); }
		uint32_t v; memcpy(&v, (const void *)spec_addr, 4);
		if (v != 2 && v != 3) { snprintf(errbuf, errlen, "guest declares machine spec %u, this host implements 2 and 3", v); return host_new_unwind(h); }
		spec = (int)v;
	  }
	  mb_threads_set_spec(h->threads, spec);
	  /* the guest kit's revision, read the same way (emulibc.c); none is 0 */
	  uintptr_t kit_addr = mb_elf_proc_addr(h->elf, "__wbx_kit_revision");
	  h->kit_revision = 0;
	  h->clock_start_ns = MB_V3_BASE_NS;
	  if (kit_addr) {
		if (!guest_owns(h, kit_addr, 4)) { snprintf(errbuf, errlen, "guest's __wbx_kit_revision points outside its memory"); return host_new_unwind(h); }
		memcpy(&h->kit_revision, (const void *)kit_addr, 4);
	  }
	  mb_threads_set_kit_revision(h->threads, h->kit_revision);
	  mb_fs_set_linux_answers(h->fs, h->kit_revision >= 2);
	  if (spec == 3) { fprintf(stderr, "miniBox: guest declares machine spec v3 (virtual time)\n"); fflush(stderr); } }

	/* every callback slot answers, registered or not */
	{ const uintptr_t none = mb_thunks_get_extcall(h->thunks, (uintptr_t)&unregistered_callback, &h->context);
	  for (size_t i = 0; none != 0 && i < MB_CALLBACK_SLOTS; i++)
		h->context.extcall_slots[i] = (mb_external_callback)none; }
	if (!call_guest_guarded(h, mb_elf_entry(h->elf))) {   /* _start */
		snprintf(errbuf, errlen, "the core died while starting: %s", h->death);
		return host_new_unwind(h);
	}
	mb_block_deactivate(h->block); h->active = false;
	return h;
}

/* What the guest last wrote to stdout/stderr, into the diagnostic log. Only for
 * paths about to end the process: it writes a file. The buffer is static because
 * this can run inside a fault handler on a stack with little room to spare. */
void mb_host_diag_guest_output(mb_host *h) {
	if (h == NULL || h->fs == NULL) return;
	static char tail[16 * 1024];
	size_t n = mb_fs_sysout_tail(h->fs, tail, sizeof tail);
	if (n == 0) { mb_diag("  (the guest wrote nothing to stdout or stderr)\n"); return; }
	mb_diag("--- the guest's last %u bytes of stdout/stderr, oldest first ---\n%.*s\n--- end of guest output ---\n",
	        (unsigned)n, (int)n, tail);
}

void mb_host_destroy(mb_host *h) {
#ifdef _WIN32
	if (h && h->have_stop_thread) CloseHandle((HANDLE)h->stop_thread);
#endif
	if (!h) return;
	/* The fault handlers read the active context through mb_guest_ctx, and every
	 * guest call sets it. A host that is gone must not be what they read: a second
	 * machine opened in the same process took its first fault against this one's
	 * freed context and wrote whatever was left there into the host's %fs. */
	if (mb_guest_ctx == &h->context) mb_guest_ctx = NULL;
#ifndef _WIN32
	/* and the spin sampler: it must be done with this host before it is freed */
	pthread_mutex_lock(&sample_lock);
	if (sample_h == h) sample_h = NULL;
	pthread_mutex_unlock(&sample_lock);
#endif
	/* The same rule for the same reason, one field over: the fault handler
	 * names the region an address landed in by reading this host's layout, and
	 * a freed host is not a layout. chimera#127 died of exactly this - the
	 * handler faulted on its own diagnosis and Windows re-entered it until the
	 * stack ran out. */
	mb_tripguard_forget_layout(&h->layout);
	if (h->active) mb_block_deactivate(h->block);
	free(h->plan_head); free(h->plan_tail);
	mb_block_free(h->block); mb_fs_free(h->fs); mb_elf_free(h->elf);
	mb_thunks_free(h->thunks); mb_threads_free(h->threads); free(h);
}

uintptr_t mb_host_proc_addr_raw(mb_host *h, const char *name);
uintptr_t mb_host_proc_addr(mb_host *h, const char *name);

/* Spin sampler (MB_SAMPLE_SECS=N). A helper thread prints the active green
 * thread + guest rsp + stack top every N seconds. Locates non-syscall spins.
 * POSIX-only, env-gated, and unobservable by the guest.
 *
 * It must never be able to take the process down, because it runs beside the
 * frontend rather than inside the guest: a fault on this thread is nobody's
 * to handle. So the stack is read with process_vm_readv on our own pid - a
 * page that is gone (or goes while we read) is an error return, not a
 * SIGSEGV - and the host it reads is held under sample_lock, which
 * mb_host_destroy takes before the host is freed. Each activate points it at
 * the live host, so a reboot does not leave it reading the first one. */
#ifndef _WIN32
static pthread_t sample_thr;
static int sample_started;
static void *sample_fn(void *arg) {
	(void)arg;
	const char *e = getenv("MB_SAMPLE_SECS");
	int secs = e ? atoi(e) : 0;
	if (secs <= 0) return NULL;
	for (;;) {
		sleep((unsigned)secs);
		pthread_mutex_lock(&sample_lock);
		struct mb_host *h = sample_h;
		if (h && h->active) {
			const uintptr_t rsp = h->context.guest_rsp;   /* racy by design: a snapshot */
			uint64_t words[12];
			struct iovec local = { words, sizeof words }, remote = { (void *)rsp, sizeof words };
			const ssize_t got = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
			fprintf(stderr, "[S] active=%u rsp=%lx stack:", mb_threads_active_tid(h->threads), (unsigned long)rsp);
			if (got == (ssize_t)sizeof words)
				for (int i = 0; i < 12; i++) fprintf(stderr, " %lx", (unsigned long)words[i]);
			else
				fprintf(stderr, " (not readable)");
			fprintf(stderr, "\n");
		}
		pthread_mutex_unlock(&sample_lock);
	}
	return NULL;
}
#endif
void mb_host_activate(mb_host *h) {
#ifndef _WIN32
	/* guest code will run on THIS thread; make signal delivery on a faulting
	 * tracked stack page possible (see tripguard.c) */
	mb_tripguard_ensure_altstack();
#endif	/* A guest that exports GuestFaultHandler wants to hear about faults on
	 * pages it protected itself (see tripguard.c) - on BOTH platforms: the
	 * Windows handler is the vectored one, and a guest whose handler is not
	 * registered there dies on its first watched write. The RAW address: it
	 * is called on the faulting guest thread, which is already inside the
	 * guest, so the host-to-guest adapter (a host thread entering) would
	 * find no entry context to save. The guest ABI is spelled in the type. */
	/* ...and entered through a thunk for a fault taken in HOST code (host C
	 * writing a protected guest page), where the thread is not inside */
	if (!h->fault_known) {
		h->fault_raw = mb_host_proc_addr_raw(h, "GuestFaultHandler");
		h->fault_entry = mb_host_proc_addr(h, "GuestFaultHandler");
		h->fault_known = true;
	}
	mb_tripguard_set_guest_fault_handler((mb_guest_fault_fn)h->fault_raw);
	mb_tripguard_set_guest_fault_entry((mb_guest_fault_fn)h->fault_entry);
#ifndef _WIN32
	static int sampling = -1;   /* MB_SAMPLE_SECS, read once */
	if (sampling < 0) sampling = getenv("MB_SAMPLE_SECS") != NULL;
	if (sampling) {
		pthread_mutex_lock(&sample_lock);
		sample_h = h;   /* the live host, every time: a reboot makes a new one */
		pthread_mutex_unlock(&sample_lock);
		if (!sample_started) {
			sample_started = 1;
			pthread_create(&sample_thr, NULL, sample_fn, NULL);
			pthread_detach(sample_thr);
		}
	}
#endif
	if (h->active) return;
	mb_prepare_thread();
	h->context.host_ptr = (uintptr_t)h;
	mb_block_activate(h->block);
	h->active = true;
}
void mb_host_deactivate(mb_host *h) {
	if (!h->active) return;
	h->context.host_ptr = 0;
	mb_block_deactivate(h->block);
	h->active = false;
}

uintptr_t mb_host_proc_addr(mb_host *h, const char *name) {
	uintptr_t p = mb_elf_proc_addr(h->elf, name);
	return p ? mb_thunks_get(h->thunks, p, &h->context) : 0;
}
uintptr_t mb_host_proc_addr_raw(mb_host *h, const char *name) { return mb_elf_proc_addr(h->elf, name); }
uintptr_t mb_host_callin_addr(mb_host *h, uintptr_t ptr) { return mb_thunks_get(h->thunks, ptr, &h->context); }

int mb_host_callback_addr(mb_host *h, mb_external_callback cb, uintptr_t slot, uintptr_t *out) {
	if (slot >= MB_CALLBACK_SLOTS) return -1;
	/* Wrapped, so the host's %fs is restored before the callback's first
	 * instruction: the interop switches stacks but not thread pointers, and a
	 * Rust guest leaves its own %fs loaded. See mb_thunks_get_extcall. */
	uintptr_t wrapped = mb_thunks_get_extcall(h->thunks, (uintptr_t)cb, &h->context);
	if (wrapped == 0) return -1;
	h->context.extcall_slots[slot] = (mb_external_callback)wrapped;
	*out = mb_get_callback_ptr(slot);
	return 0;
}

/* The second the machine's clock starts at (owner, 2026-10-24, chimera#366):
 * May 27, 2017 unless told otherwise, the same for every run, so a movie
 * replays; a project may choose another to give a game other luck. Told
 * before the core first runs, and never after the machine is sealed: a state
 * does not carry it, so a machine taken back to a state must already have it. */
int mb_host_set_clock_start(mb_host *h, uint64_t unix_seconds, char *errbuf, size_t errlen) {
	if (h->sealed) { snprintf(errbuf, errlen, "the clock's start is set before the machine is sealed"); return -1; }
	if (unix_seconds > MB_CLOCK_START_MAX_SEC) { snprintf(errbuf, errlen, "the clock cannot start later than 2200-01-01"); return -1; }
	h->clock_start_ns = unix_seconds * 1000000000ull;
	return 0;
}

int mb_host_seal(mb_host *h, char *errbuf, size_t errlen) {
	if (h->sealed) { snprintf(errbuf, errlen, "Already sealed!"); return -1; }
	bool was_active = h->active;
	mb_host_activate(h);
	if (!run_proc_if_present(h, "co_clean") || !run_proc_if_present(h, "ecl_seal")) {
		snprintf(errbuf, errlen, "the core died while sealing: %s", h->death);
		if (!was_active) mb_host_deactivate(h);
		return -1;
	}
	mb_elf_seal(h->elf, h->block);
	if (mb_block_seal(h->block) != 0) { snprintf(errbuf, errlen, "seal failed"); return -1; }
	if (!was_active) mb_host_deactivate(h);
	h->sealed = true;
	return 0;
}

int mb_host_mount(mb_host *h, const char *name, const uint8_t *data, size_t len, bool writable) {
	return mb_fs_mount(h->fs, name, data, len, writable);
}
int mb_host_mount_path(mb_host *h, const char *name, const char *path) {
	return mb_fs_mount_path(h->fs, name, path);
}
int mb_host_unmount(mb_host *h, const char *name, uint8_t **out, size_t *outlen) {
	return mb_fs_unmount(h->fs, name, out, outlen);
}

size_t  mb_host_page_len(mb_host *h) { return mb_block_page_len(h->block); }
const uint8_t *mb_host_hash(mb_host *h) { return mb_block_hash(h->block); }
uint8_t mb_host_page_info(mb_host *h, size_t i) { return mb_block_page_info(h->block, i); }

/* ---- top-level save/load (structure per docs/docs/MACHINE-SPEC.md section 6) ---- */

static const char SAVE_START[] = "ActivatedWaterboxHost_v1";
/* SAVE_END: the reference's upside-down "ActivatedWaterboxHost" (UTF-8 bytes) */
static const char SAVE_END[] = "\xcb\x87soHxoq\xc9\xaf\xc7\x9d\xca\x87\xc9\x90Mp\xc7\x9d\xca\x87\xc9\x90\xca\x8c\xe1\xb4\x89\xca\x87\xc9\x94\xe2\x88\x80";

static int w_all(mb_write_cb w, uintptr_t ud, const void *d, size_t n) { return w(ud, (const uint8_t *)d, n) < 0 ? -1 : 0; }
static int r_all(mb_read_cb r, uintptr_t ud, void *d, size_t n) {
	uint8_t *p = (uint8_t *)d;
	while (n) { intptr_t g = r(ud, p, n); if (g <= 0) return -1; p += g; n -= (size_t)g; }
	return 0;
}

/* The open files and the getrandom stream (2026-10-18), after the thread set
 * in states and deltas alike. Part of the machine: a guest that closed one
 * disc and opened the next got the same descriptor, and a load to before the
 * swap went on reading the second disc; a guest that reads on without seeking
 * read from where the abandoned future had left the file. A delta carries it
 * whole, like the thread set, and composing two keeps the later one's (it is
 * in the tail that mb_host_delta_compose copies). A state or delta from
 * before has no record; it loads leaving both as they are. */
static int expect(mb_read_cb r, uintptr_t ud, const char *magic, size_t n);
static const char FILES_MAGIC[] = "OpenFileTable1";
#define FILES_MAGIC_LEN 14

static int files_save(mb_host *h, mb_write_cb w, uintptr_t ud) {
	if (w_all(w, ud, FILES_MAGIC, FILES_MAGIC_LEN)) return -1;
	if (w_all(w, ud, &h->getrandom_state, sizeof(h->getrandom_state))) return -1;
	return mb_fs_save_handles(h->fs, w, ud);
}

/* After the thread set: the record when there is one, then the end magic. */
static int files_load_then_end(mb_host *h, mb_read_cb r, uintptr_t ud, char *errbuf, size_t errlen) {
	_Static_assert(sizeof(SAVE_END) - 1 > FILES_MAGIC_LEN, "the end magic is told apart by its start");
	uint8_t m[FILES_MAGIC_LEN];
	if (r_all(r, ud, m, sizeof(m))) { snprintf(errbuf, errlen, "bad end magic"); return -1; }
	if (memcmp(m, FILES_MAGIC, FILES_MAGIC_LEN) == 0) {
		uint64_t entropy;
		if (r_all(r, ud, &entropy, sizeof(entropy)) || mb_fs_load_handles(h->fs, r, ud) < 0) {
			snprintf(errbuf, errlen, "open files load failed"); return -1;
		}
		h->getrandom_state = entropy;
		if (expect(r, ud, SAVE_END, sizeof(SAVE_END)-1)) { snprintf(errbuf, errlen, "bad end magic"); return -1; }
		return 0;
	}
	if (memcmp(m, SAVE_END, FILES_MAGIC_LEN) != 0
		|| expect(r, ud, SAVE_END + FILES_MAGIC_LEN, sizeof(SAVE_END)-1-FILES_MAGIC_LEN)) {
		snprintf(errbuf, errlen, "bad end magic"); return -1;
	}
	return 0;
}

int mb_host_save_state(mb_host *h, mb_write_cb w, uintptr_t ud, char *errbuf, size_t errlen) {
	if (!h->sealed) { snprintf(errbuf, errlen, "Not sealed!"); return -1; }
	bool was_active = h->active; mb_host_activate(h);
	int rc = -1;
	/* Phase 1 FS is fixed (mounted files only, no per-file dynamic state churn):
	 * the memory block carries all mutable machine state. FS/thread records are
	 * placeholders matching the format's magic framing. */
	if (w_all(w, ud, SAVE_START, sizeof(SAVE_START)-1)) goto done;
	if (w_all(w, ud, "FileSystem", 10) || w_all(w, ud, "FileSystemEnd", 13)) goto done;
	if (w_all(w, ud, &h->program_break, sizeof(h->program_break))) goto done;
	if (w_all(w, ud, "ElfLoader", 9) || w_all(w, ud, mb_elf_hash(h->elf), 32)) goto done;
	if (mb_block_save_state(h->block, w, ud) != 0) goto done;
	if (mb_threads_save(h->threads, &h->context, w, ud) != 0) goto done;
	if (files_save(h, w, ud)) goto done;
	if (w_all(w, ud, SAVE_END, sizeof(SAVE_END)-1)) goto done;
	rc = 0;
done:
	if (!was_active) mb_host_deactivate(h);
	if (rc) snprintf(errbuf, errlen, "save_state write failed");
	return rc;
}

/* ---- a whole machine, taken while it runs --------------------------------
 *
 * mb_host_save_state writes the machine through a callback and waits for it.
 * Almost all of what that costs is the page copy - 40 to 180 ms for a 257 MB
 * machine, once per anchor, on the thread that runs the emulator. The pages can
 * be copied later, and elsewhere, if they are held still meanwhile: see
 * mb_block_state_plan.
 *
 * Everything AROUND the pages is small and has to describe the machine at the
 * moment the state was asked for, so it is written now, into the caller's
 * buffer, and the pages are what arrives late.
 *
 *   size  = mb_host_state_size(h)          what it will weigh
 *   plan  = mb_host_state_plan(h, dest)    the surround, and the pages held
 *   fill  = mb_host_state_fill(h, a, b)    a range of pages, on any thread
 *   done  = mb_host_state_finish(h)        the rest, and the holds lifted
 *
 * The buffer belongs to the caller and must outlive the plan. Between plan and
 * finish the guest may run; a write to a page nobody has copied yet is copied
 * by the fault handler before the write lands.
 */

typedef struct { uint8_t *p; size_t cap, n; } mb_memsink;

static int32_t memsink_write(uintptr_t ud, const uint8_t *data, uintptr_t size) {
	mb_memsink *s = (mb_memsink *)ud;
	if (s->n + size > s->cap) return -1;
	memcpy(s->p + s->n, data, size);
	s->n += size;
	return 0;
}

/* The surround, into h->plan_head and h->plan_tail, so that both the size and
 * the plan agree to the byte about what goes where. */
static int host_state_surround(mb_host *h) {
	free(h->plan_head); h->plan_head = NULL; h->plan_head_len = 0;
	free(h->plan_tail); h->plan_tail = NULL; h->plan_tail_len = 0;

	/* generous: the surround is magic strings, a pointer, a hash and the thread
	 * records, none of which is near this */
	const size_t room = 1u << 20;
	h->plan_head = (uint8_t *)malloc(room);
	h->plan_tail = (uint8_t *)malloc(room);
	if (!h->plan_head || !h->plan_tail) return -1;

	mb_memsink head = { h->plan_head, room, 0 };
	if (w_all(memsink_write, (uintptr_t)&head, SAVE_START, sizeof(SAVE_START) - 1)) return -1;
	if (w_all(memsink_write, (uintptr_t)&head, "FileSystem", 10)) return -1;
	if (w_all(memsink_write, (uintptr_t)&head, "FileSystemEnd", 13)) return -1;
	if (w_all(memsink_write, (uintptr_t)&head, &h->program_break, sizeof(h->program_break))) return -1;
	if (w_all(memsink_write, (uintptr_t)&head, "ElfLoader", 9)) return -1;
	if (w_all(memsink_write, (uintptr_t)&head, mb_elf_hash(h->elf), 32)) return -1;
	h->plan_head_len = head.n;

	mb_memsink tail = { h->plan_tail, room, 0 };
	if (mb_threads_save(h->threads, &h->context, memsink_write, (uintptr_t)&tail) != 0) return -1;
	if (files_save(h, memsink_write, (uintptr_t)&tail)) return -1;
	if (w_all(memsink_write, (uintptr_t)&tail, SAVE_END, sizeof(SAVE_END) - 1)) return -1;
	h->plan_tail_len = tail.n;
	return 0;
}

size_t mb_host_state_size(mb_host *h) {
	if (!h->sealed) return 0;
	bool was_active = h->active; mb_host_activate(h);
	size_t total = 0;
	if (host_state_surround(h) == 0) {
		const size_t block = mb_block_state_size(h->block);
		if (block != 0) total = h->plan_head_len + block + h->plan_tail_len;
	}
	if (!was_active) mb_host_deactivate(h);
	return total;
}

size_t mb_host_state_plan(mb_host *h, uint8_t *dest, size_t size) {
	if (!h->sealed || dest == NULL || h->plan_head == NULL) return 0;
	if (size < h->plan_head_len + h->plan_tail_len) return 0;
	bool was_active = h->active; mb_host_activate(h);
	size_t total = 0;
	/* The block plans within the room left and says how much it took: asking
	 * its size first walked every page once more (2026-10-18). */
	memcpy(dest, h->plan_head, h->plan_head_len);
	const size_t data_at = mb_block_state_plan_within(h->block, dest + h->plan_head_len,
	                                                  size - h->plan_head_len - h->plan_tail_len);
	if (data_at != 0) {
		const size_t block = data_at + mb_block_plan_count(h->block) * MB_PAGESIZE;
		memcpy(dest + h->plan_head_len + block, h->plan_tail, h->plan_tail_len);
		total = h->plan_head_len + block + h->plan_tail_len;
	}
	if (!was_active) mb_host_deactivate(h);
	return total;
}

size_t mb_host_state_pages(mb_host *h) { return mb_block_plan_count(h->block); }

size_t mb_host_state_fill(mb_host *h, size_t from, size_t to) {
	return mb_block_plan_fill(h->block, from, to);
}

int mb_host_state_finish(mb_host *h) {
	bool was_active = h->active; mb_host_activate(h);
	const int rc = mb_block_plan_finish(h->block);
	if (!was_active) mb_host_deactivate(h);
	return rc;
}

static int expect(mb_read_cb r, uintptr_t ud, const char *magic, size_t n) {
	char buf[64]; if (n > sizeof(buf)) return -1;
	if (r_all(r, ud, buf, n)) return -1;
	return memcmp(buf, magic, n) == 0 ? 0 : -1;
}

/* A load that failed after it began replacing memory leaves a mix of two
 * machines. MACHINE-SPEC says such a load poisons the instance, and now it
 * does: the machine is dead until a state loads, as after a crash, so no
 * caller plays on, records or stores it (2026-10-18). A refusal that left the
 * machine as it was (another build's or another boot's state) does not. */
static void poison_half_loaded(mb_host *h, const char *why) {
	if (!h->block->load_touched) return;
	h->context.dead = 1;
	snprintf(h->death, sizeof h->death,
	         "a state stopped loading half way (%s); the machine is a mix of two and runs nothing until a state loads",
	         why);
	mb_diag_banner("the guest died");
	mb_diag("miniBox: %s\n", h->death);
}

int mb_host_load_state(mb_host *h, mb_read_cb r, uintptr_t ud, char *errbuf, size_t errlen) {
	if (!h->sealed) { snprintf(errbuf, errlen, "Not sealed!"); return -1; }
	bool was_active = h->active; mb_host_activate(h);
	/* A machine that died on another thread than the first is still "on" that
	 * thread, and a thread set only loads onto a machine on its first. The load
	 * replaces every thread anyway. */
	if (h->context.dead) mb_threads_reset_active(h->threads);
	h->block->load_touched = false;   /* until the block says otherwise */
	int rc = -1;
	uint8_t elfhash[32];
	/* The state's break is the machine's only once its memory is: a state
	 * refused below (another build's, another boot's) leaves both as they were.
	 * Taken at once, a refused load handed the host a foreign break while the
	 * guest's C library kept its own, and the next heap growth went wrong. */
	uintptr_t brk = 0;
	if (expect(r, ud, SAVE_START, sizeof(SAVE_START)-1)) { snprintf(errbuf, errlen, "bad start magic"); goto done; }
	if (expect(r, ud, "FileSystem", 10) || expect(r, ud, "FileSystemEnd", 13)) { snprintf(errbuf, errlen, "bad fs magic"); goto done; }
	if (r_all(r, ud, &brk, sizeof(brk))) goto done;
	if (expect(r, ud, "ElfLoader", 9)) { snprintf(errbuf, errlen, "bad elf magic"); goto done; }
	if (r_all(r, ud, elfhash, 32)) goto done;
	if (memcmp(elfhash, mb_elf_hash(h->elf), 32) != 0) { snprintf(errbuf, errlen, "ELF hash mismatch"); goto done; }
	if (mb_block_load_state(h->block, r, ud) != 0) { snprintf(errbuf, errlen, "memory block load failed"); goto done; }
	h->program_break = brk;
	if (mb_threads_load(h->threads, &h->context, r, ud) != 0) { snprintf(errbuf, errlen, "thread set load failed"); goto done; }
	if (files_load_then_end(h, r, ud, errbuf, errlen)) goto done;
	rc = 0;
	/* a whole machine that did exist: whatever killed the last one is gone */
	h->context.dead = 0;
	h->death[0] = '\0';
done:
	if (rc != 0) poison_half_loaded(h, errbuf);
	if (!was_active) mb_host_deactivate(h);
	return rc;
}

/* ---- epochs and deltas (see minibox_internal.h) ----
 *
 * A savestate is the whole machine; a delta is one epoch's worth of it. The
 * memory half is the block's (mb_block_delta_save), and this adds the small
 * non-memory half - the program break and the thread set - which is a few
 * kilobytes and is simply carried whole rather than differenced.
 */

static const char DELTA_START[] = "MiniBoxHostDelta_v1";

/* a growable buffer, so the thread set can be captured at epoch time */
typedef struct { uint8_t *buf; size_t len, cap, pos; } hostbuf;
static int32_t hostbuf_write(uintptr_t ud, const uint8_t *d, uintptr_t n) {
	hostbuf *m = (hostbuf *)ud;
	if (m->len + n > m->cap) {
		size_t cap = (m->len + n) * 2 + 64;
		uint8_t *nb = (uint8_t *)realloc(m->buf, cap);
		if (!nb) return -1;
		m->buf = nb; m->cap = cap;
	}
	memcpy(m->buf + m->len, d, n); m->len += n;
	return 0;
}
static intptr_t hostbuf_read(uintptr_t ud, uint8_t *d, uintptr_t n) {
	hostbuf *m = (hostbuf *)ud;
	uintptr_t avail = m->len - m->pos;
	if (n > avail) n = avail;
	if (n == 0) return -1;
	memcpy(d, m->buf + m->pos, n); m->pos += n;
	return (intptr_t)n;
}

int mb_host_epoch_begin(mb_host *h, char *errbuf, size_t errlen) {
	if (!h->sealed) { snprintf(errbuf, errlen, "Not sealed!"); return -1; }
	bool was_active = h->active; mb_host_activate(h);
	int rc = -1;
	if (mb_block_epoch_begin(h->block) != 0) { snprintf(errbuf, errlen, "epoch begin failed"); goto done; }
	h->epoch_brk = h->program_break;
	free(h->epoch_threads); h->epoch_threads = NULL; h->epoch_threads_len = 0;
	{
		hostbuf t = { 0 };
		/* the thread set and the open files, as a reverse delta will want them */
		if (mb_threads_save(h->threads, &h->context, hostbuf_write, (uintptr_t)&t) != 0
			|| files_save(h, hostbuf_write, (uintptr_t)&t) != 0) {
			free(t.buf);
			snprintf(errbuf, errlen, "thread set capture failed");
			goto done;
		}
		h->epoch_threads = t.buf; h->epoch_threads_len = t.len;
	}
	rc = 0;
done:
	if (!was_active) mb_host_deactivate(h);
	return rc;
}

int mb_host_delta_save(mb_host *h, bool forward, mb_write_cb w, uintptr_t ud, char *errbuf, size_t errlen) {
	if (!h->sealed) { snprintf(errbuf, errlen, "Not sealed!"); return -1; }
	if (!forward && h->epoch_threads == NULL) { snprintf(errbuf, errlen, "no epoch to reverse"); return -1; }
	bool was_active = h->active; mb_host_activate(h);
	int rc = -1;
	uintptr_t brk = forward ? h->program_break : h->epoch_brk;
	if (w_all(w, ud, DELTA_START, sizeof(DELTA_START)-1)) goto done;
	if (w_all(w, ud, &brk, sizeof(brk))) goto done;
	if (w_all(w, ud, mb_elf_hash(h->elf), 32)) goto done;
	if (mb_block_delta_save(h->block, forward, w, ud) != 0) { snprintf(errbuf, errlen, "memory delta failed"); goto done; }
	if (forward) {
		if (mb_threads_save(h->threads, &h->context, w, ud) != 0) goto done;
		if (files_save(h, w, ud)) goto done;
	} else {
		if (w_all(w, ud, h->epoch_threads, h->epoch_threads_len)) goto done;
	}
	if (w_all(w, ud, SAVE_END, sizeof(SAVE_END)-1)) goto done;
	rc = 0;
done:
	if (!was_active) mb_host_deactivate(h);
	if (rc) snprintf(errbuf, errlen, "delta write failed");
	return rc;
}

int mb_host_delta_apply(mb_host *h, mb_read_cb r, uintptr_t ud, char *errbuf, size_t errlen) {
	if (!h->sealed) { snprintf(errbuf, errlen, "Not sealed!"); return -1; }
	bool was_active = h->active; mb_host_activate(h);
	h->block->load_touched = false;   /* until the block says otherwise */
	int rc = -1;
	uint8_t elfhash[32];
	/* the delta's break is taken with its memory, as in mb_host_load_state */
	uintptr_t brk = 0;
	if (expect(r, ud, DELTA_START, sizeof(DELTA_START)-1)) { snprintf(errbuf, errlen, "bad delta magic"); goto done; }
	if (r_all(r, ud, &brk, sizeof(brk))) goto done;
	if (r_all(r, ud, elfhash, 32)) goto done;
	if (memcmp(elfhash, mb_elf_hash(h->elf), 32) != 0) { snprintf(errbuf, errlen, "ELF hash mismatch"); goto done; }
	if (mb_block_delta_apply(h->block, r, ud) != 0) { snprintf(errbuf, errlen, "memory delta apply failed"); goto done; }
	h->program_break = brk;
	if (mb_threads_load(h->threads, &h->context, r, ud) != 0) { snprintf(errbuf, errlen, "thread set load failed"); goto done; }
	if (files_load_then_end(h, r, ud, errbuf, errlen)) goto done;
	/* the epoch is spent: it described the machine we have just left */
	free(h->epoch_threads); h->epoch_threads = NULL; h->epoch_threads_len = 0;
	rc = 0;
done:
	if (rc != 0) poison_half_loaded(h, errbuf);
	if (!was_active) mb_host_deactivate(h);
	return rc;
}

/* Two forward deltas as one. See mb_block_delta_compose: the block's lists
 * merge, and everything outside them - where the program break ended, which
 * threads there are - is taken from the LATER delta, because that is the
 * machine the pair lands on.
 *
 * No host is touched. A history composes deltas it is merely storing, which it
 * must be able to do with no machine loaded and none of these bytes live. */
int mb_host_delta_compose(mb_read_cb ra, uintptr_t uda, mb_read_cb rb, uintptr_t udb,
                          mb_write_cb w, uintptr_t ud, char *errbuf, size_t errlen) {
	uintptr_t brk_a = 0, brk_b = 0;
	uint8_t hash_a[32], hash_b[32];
	if (expect(ra, uda, DELTA_START, sizeof(DELTA_START)-1)
		|| expect(rb, udb, DELTA_START, sizeof(DELTA_START)-1)) {
		snprintf(errbuf, errlen, "bad delta magic"); return -1;
	}
	if (r_all(ra, uda, &brk_a, sizeof(brk_a)) || r_all(ra, uda, hash_a, 32)
		|| r_all(rb, udb, &brk_b, sizeof(brk_b)) || r_all(rb, udb, hash_b, 32)) {
		snprintf(errbuf, errlen, "delta read failed"); return -1;
	}
	(void)brk_a;
	if (memcmp(hash_a, hash_b, 32) != 0) {
		snprintf(errbuf, errlen, "deltas are of different machines"); return -1;
	}
	if (w_all(w, ud, DELTA_START, sizeof(DELTA_START)-1)
		|| w_all(w, ud, &brk_b, sizeof(brk_b)) || w_all(w, ud, hash_b, 32)) {
		snprintf(errbuf, errlen, "delta write failed"); return -1;
	}
	if (mb_block_delta_compose(ra, uda, rb, udb, w, ud) != 0) {
		snprintf(errbuf, errlen, "memory delta compose failed"); return -1;
	}
	/* Whatever the later delta has left - its thread set and its end magic -
	 * goes out verbatim. Its length is the thread set's business, so this
	 * copies to the end of the stream rather than parsing what it does not own. */
	for (;;) {
		uint8_t buf[65536];
		intptr_t got = rb(udb, buf, sizeof(buf));
		if (got <= 0) break;
		if (w_all(w, ud, buf, (size_t)got)) { snprintf(errbuf, errlen, "delta write failed"); return -1; }
	}
	return 0;
}

/* The same for two deltas already in memory (mb_block_delta_compose_mem). The
 * history composes every frame and holds both deltas contiguously, so reading
 * them in through a callback was copying megabytes to look at megabytes. */
int mb_host_delta_compose_mem(const uint8_t *abuf, size_t alen, const uint8_t *bbuf, size_t blen,
                              mb_write_cb w, uintptr_t ud, char *errbuf, size_t errlen) {
	const size_t head = sizeof(DELTA_START) - 1, stamp = sizeof(uintptr_t) + 32;
	if (alen < head + stamp || blen < head + stamp
		|| memcmp(abuf, DELTA_START, head) != 0 || memcmp(bbuf, DELTA_START, head) != 0) {
		snprintf(errbuf, errlen, "bad delta magic"); return -1;
	}
	const uint8_t *ap = abuf + head, *bp = bbuf + head;
	uintptr_t brk_b;
	memcpy(&brk_b, bp, sizeof(brk_b));
	if (memcmp(ap + sizeof(uintptr_t), bp + sizeof(uintptr_t), 32) != 0) {
		snprintf(errbuf, errlen, "deltas are of different machines"); return -1;
	}
	if (w_all(w, ud, DELTA_START, head) || w_all(w, ud, &brk_b, sizeof(brk_b))
		|| w_all(w, ud, bp + sizeof(uintptr_t), 32)) {
		snprintf(errbuf, errlen, "delta write failed"); return -1;
	}
	ap += stamp; bp += stamp;
	size_t used = 0;
	if (mb_block_delta_compose_mem(ap, alen - (size_t)(ap - abuf), bp, blen - (size_t)(bp - bbuf),
			w, ud, &used) != 0) {
		snprintf(errbuf, errlen, "memory delta compose failed"); return -1;
	}
	/* the later delta's thread set and end magic, verbatim */
	const size_t tail = blen - (size_t)(bp - bbuf) - used;
	if (tail != 0 && w_all(w, ud, bp + used, tail)) {
		snprintf(errbuf, errlen, "delta write failed"); return -1;
	}
	return 0;
}

size_t mb_host_epoch_page_count(const mb_host *h) {
	return mb_block_epoch_page_count(h->block);
}
