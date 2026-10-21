#define _GNU_SOURCE   /* setenv/unsetenv for the abort check; this file is built -std=c11 */
/* End-to-end + corner-case system test: loads guest.wbx through the miniBox C
 * host and exercises the whole phase-1 stack - ELF load, __wbxsysinfo, guest
 * execution via the interop trampolines, guest syscalls (stderr, brk, a mounted
 * file read), sealed/invisible memory, a guest->host callback, savestate
 * round-trip + determinism, and the error/poison paths. */
#include "minibox.h"
#include <assert.h>
/* For the two checks on the fault handler's own state: what it would name a
 * region with, and (on Windows) pointing it somewhere it cannot read on
 * purpose. Both are internal to the host, and a test is the one caller. */
#include "minibox_internal.h"
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#ifndef _WIN32
#include <pthread.h>
#include <signal.h>
#endif
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif
#ifndef _WIN32
#include <sys/syscall.h>
#include <unistd.h>
/* The host thread's %fs base: where glibc - and a runtime like Mono - keep this
 * thread's state. Nothing done on behalf of a guest that does not use %fs may
 * change it. */
static uintptr_t host_fs_base(void) {
	uintptr_t v = 0;
#if defined(__aarch64__)
	/* aarch64: TPIDR_EL0, where glibc keeps this thread's state */
	__asm__ volatile ("mrs %0, tpidr_el0" : "=r" (v));
#elif defined(__x86_64__)
	syscall(SYS_arch_prctl, 0x1003 /* ARCH_GET_FS */, &v);
#else
#error "miniBox runs on x86-64 and aarch64 only"
#endif
	return v;
}
#endif

typedef struct { FILE *f; } freader;
static intptr_t file_read(uintptr_t ud, uint8_t *data, uintptr_t size) {
	return (intptr_t)fread(data, 1, size, ((freader *)ud)->f);
}
typedef struct { const uint8_t *p; size_t n, pos; } memreader;
static intptr_t mem_reader(uintptr_t ud, uint8_t *data, uintptr_t size) {
	memreader *m = (memreader *)ud;
	size_t take = size < (m->n - m->pos) ? size : (m->n - m->pos);
	memcpy(data, m->p + m->pos, take); m->pos += take; return (intptr_t)take;
}
typedef struct { uint8_t *buf; size_t len, cap, pos; } membuf;

/* does a savestate buffer contain a byte string (thread-set magic check) */
static bool state_contains(membuf *m, const char *s) {
	size_t n = strlen(s);
	if (n == 0 || m->len < n) return false;
	for (size_t i = 0; i + n <= m->len; i++)
		if (memcmp(m->buf + i, s, n) == 0) return true;
	return false;
}static int32_t mem_write(uintptr_t ud, const uint8_t *data, uintptr_t n) {
	membuf *m = (membuf *)ud;
	if (m->len + n > m->cap) { m->cap = (m->len + n) * 2 + 64; m->buf = realloc(m->buf, m->cap); }
	memcpy(m->buf + m->len, data, n); m->len += n; return 0;
}
static intptr_t mem_read(uintptr_t ud, uint8_t *data, uintptr_t n) {
	membuf *m = (membuf *)ud;
	uintptr_t avail = m->len - m->pos; if (n > avail) n = avail;
	memcpy(data, m->buf + m->pos, n); m->pos += n; return (intptr_t)n;
}

static int fails = 0;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "  FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)
/* Stage markers on stderr, which is unbuffered: when the host aborts or the
 * process dies, buffered stdout is lost, and the last thing seen is whatever
 * the GUEST printed (its writes go through the host's stderr). That reads as
 * "it stopped right after guest init" no matter where it really stopped. */
#define STAGE(...) do { fprintf(stderr, "[stage] " __VA_ARGS__); fputc('\n', stderr); fflush(stderr); } while (0)

/* guest->host callback (slot 0): record the last logged accumulator value.
 *
 * MB_GUEST_ABI is NOT decoration: the guest calls this through the interop blob,
 * which is sysv64. Compiled win64 on Windows, the callee would spill registers
 * into 32 bytes of shadow space that a sysv64 caller never reserved - straight
 * over the blob's own stack - and the return path would then read a garbage
 * context pointer and fault. Any callback handed to wbx_get_callback_addr needs
 * this. */
static uint64_t g_last_log = 0;
/* the floating-point control words the callback ran with (see the FPU checks) */
static uint16_t g_cb_fcw;
static uint32_t g_cb_mxcsr;
#if defined(__x86_64__)
static void host_fpu_get(uint16_t *cw, uint32_t *mx) { __asm__ volatile("fnstcw %0\n\tstmxcsr %1" : "=m"(*cw), "=m"(*mx)); }
static void host_fpu_set(uint16_t cw, uint32_t mx) { __asm__ volatile("fldcw %0\n\tldmxcsr %1" : : "m"(cw), "m"(mx)); }
#define FPU_FLAGS 0x3Fu   /* MXCSR's sticky exception flags: not compared */
#define FPU_START_CW 0x037F   /* what every guest starts with */
#define FPU_START_MX 0x1F80
#define FPU_HOST_CW  0x027F   /* Windows' default: 53-bit precision */
#define FPU_HOST_MX  0x7F80   /* round toward zero */
#define FPU_GUEST_CW 0x077F   /* round down, both units */
#define FPU_GUEST_MX 0x3F80
#elif defined(__aarch64__)
/* aarch64 has FPCR alone, in the MXCSR place; the x87 word is always 0, and
 * FPCR keeps no sticky flags (those are FPSR's) */
static void host_fpu_get(uint16_t *cw, uint32_t *mx) { uint64_t v; __asm__ volatile("mrs %0, fpcr" : "=r"(v)); *cw = 0; *mx = (uint32_t)v; }
static void host_fpu_set(uint16_t cw, uint32_t mx) { (void)cw; __asm__ volatile("msr fpcr, %0" : : "r"((uint64_t)mx)); }
#define FPU_FLAGS 0u
#define FPU_START_CW 0
#define FPU_START_MX 0            /* round to nearest, no flushing */
#define FPU_HOST_CW  0
#define FPU_HOST_MX  0x00C00000u  /* RMode: round toward zero */
#define FPU_GUEST_CW 0
#define FPU_GUEST_MX 0x00800000u  /* RMode: round down */
#else
#error "miniBox runs on x86-64 and aarch64 only"
#endif

static uintptr_t MB_GUEST_ABI log_cb(uintptr_t v, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t a6) {
	(void)a2;(void)a3;(void)a4;(void)a5;(void)a6; g_last_log = (uint32_t)v;
	host_fpu_get(&g_cb_fcw, &g_cb_mxcsr);
	return 0;
}

/* The guest is sysv64 whatever the host is; MB_GUEST_ABI (minibox.h) makes that
 * explicit, which matters on a win64 host and expands to nothing on Linux. */
typedef int      (MB_GUEST_ABI *init_fn)(void);
typedef uint32_t (MB_GUEST_ABI *step_fn)(uint32_t);
typedef uint64_t (MB_GUEST_ABI *getacc_fn)(void);
typedef void     (MB_GUEST_ABI *setcb_fn)(uintptr_t);

static uintptr_t proc(mb_host *h, const char *name) {
	mb_return r; wbx_get_proc_addr(h, name, &r);
	if (r.error_message[0]) { fprintf(stderr, "get_proc_addr(%s): %s\n", name, r.error_message); exit(2); }
	return r.data;
}

/* create a fresh host from the guest path, with the seed file mounted */
static mb_host *make_host(const char *path, uint32_t seed) {
	FILE *f = fopen(path, "rb");
	if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
	mb_memory_layout_template layout = {
		.sbrk_size = 16u<<20, .sealed_size = 16u<<20, .invis_size = 16u<<20,
		.plain_size = 16u<<20, .mmap_size = 32u<<20,
	};
	freader fr = { f };
	mb_return r;
	/* made from a host at Windows' default control words (see the FPU
	 * checks in main): the guest's start-up code still runs with
	 * 0x37F/0x1F80 (aarch64: FPCR 0), and the host has its own back
	 * afterwards */
	uint16_t create_cw; uint32_t create_mx;
	host_fpu_get(&create_cw, &create_mx);
	host_fpu_set(FPU_HOST_CW, FPU_HOST_MX);
	wbx_create_host(&layout, "guest.wbx", file_read, (uintptr_t)&fr, &r);
	uint16_t created_cw; uint32_t created_mx;
	host_fpu_get(&created_cw, &created_mx);
	host_fpu_set(create_cw, create_mx);
	CHECK(created_cw == FPU_HOST_CW && (created_mx & ~FPU_FLAGS) == FPU_HOST_MX);
	fclose(f);
	if (r.error_message[0]) { fprintf(stderr, "create_host: %s\n", r.error_message); exit(1); }
	mb_host *h = (mb_host *)r.data;
	/* mount the seed as a readonly file BEFORE Init/seal (stable across states) */
	memreader mr = { (const uint8_t *)&seed, sizeof(seed), 0 };
	wbx_mount_file(h, "seed", mem_reader, (uintptr_t)&mr, false, &r);
	CHECK(!r.error_message[0]);
	/* two read-only discs for the open-files checks: byte i of disc N is
	 * N * 0x40 + i */
	static uint8_t disc1[64], disc2[64];
	for (int i = 0; i < 64; i++) { disc1[i] = (uint8_t)(0x40 + i); disc2[i] = (uint8_t)(0x80 + i); }
	memreader d1 = { disc1, sizeof disc1, 0 }, d2 = { disc2, sizeof disc2, 0 };
	wbx_mount_file(h, "disc1", mem_reader, (uintptr_t)&d1, false, &r);
	CHECK(!r.error_message[0]);
	wbx_mount_file(h, "disc2", mem_reader, (uintptr_t)&d2, false, &r);
	CHECK(!r.error_message[0]);
	return h;
}

/* A v3 host: seed readonly plus a writable scratch file for the O_TRUNC case */
static void seal_and_activate(mb_host *h);
static mb_host *make_v3_host(const char *path) {
	FILE *f = fopen(path, "rb");
	if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
	mb_memory_layout_template layout = {
		.sbrk_size = 16u<<20, .sealed_size = 16u<<20, .invis_size = 16u<<20,
		.plain_size = 16u<<20, .mmap_size = 32u<<20,
	};
	freader fr = { f };
	mb_return r;
	wbx_create_host(&layout, "guest-v3.wbx", file_read, (uintptr_t)&fr, &r);
	fclose(f);
	if (r.error_message[0]) { fprintf(stderr, "create_host: %s\n", r.error_message); exit(1); }
	mb_host *h = (mb_host *)r.data;
	uint32_t seed = 0xABCD;
	memreader mr = { (const uint8_t *)&seed, sizeof(seed), 0 };
	wbx_mount_file(h, "seed", mem_reader, (uintptr_t)&mr, false, &r);
	CHECK(!r.error_message[0]);
	static uint8_t scratch_init[1] = { 'X' };
	memreader sr = { scratch_init, sizeof scratch_init, 0 };
	wbx_mount_file(h, "scratch", mem_reader, (uintptr_t)&sr, true, &r);
	CHECK(!r.error_message[0]);
	return h;
}

/* Spec v3 end to end: a guest declaring __wbx_machine_spec = 3. Fresh host
 * per export group is unnecessary; one host runs the clock/sleep/wait/memory
 * checks in order (each is self-contained), then the save/load dance around
 * a parked timed waiter, then the v3 magic check. */
#ifndef _WIN32
/* A thread whose runtime gave it a small alternate signal stack (Mono and
 * .NET give 16 KiB) gets one big enough for the fault handler's report when
 * it activates a machine (2026-10-18). Returns the size it ends up with. */
static void *small_altstack_thread(void *arg) {
	mb_host *h = (mb_host *)arg;
	static uint8_t small[16384];
	stack_t ss = { .ss_sp = small, .ss_flags = 0, .ss_size = sizeof small };
	sigaltstack(&ss, NULL);
	mb_return r;
	wbx_activate_host(h, &r);
	stack_t now;
	sigaltstack(NULL, &now);
	wbx_deactivate_host(h, &r);
	return (void *)(uintptr_t)now.ss_size;
}
#endif

/* A guest that dies in its start-up code, and one that dies while it is
 * sealed: the host says why and lives on (2026-10-18). */
static int dies_starting_or_sealing(const char *starting, const char *sealing) {
	mb_memory_layout_template layout = {
		.sbrk_size = 16u<<20, .sealed_size = 16u<<20, .invis_size = 16u<<20,
		.plain_size = 16u<<20, .mmap_size = 32u<<20,
	};
	mb_return r;
	FILE *f = fopen(starting, "rb");
	if (!f) { fprintf(stderr, "cannot open %s\n", starting); return 1; }
	freader fr = { f };
	wbx_create_host(&layout, "guest-dies-1.wbx", file_read, (uintptr_t)&fr, &r);
	fclose(f);
	printf("run_guest: a guest dying in its start-up code: %s\n", r.error_message);
	CHECK(strstr(r.error_message, "died while starting") != NULL && strstr(r.error_message, "crashed") != NULL);
	f = fopen(sealing, "rb");
	if (!f) { fprintf(stderr, "cannot open %s\n", sealing); return 1; }
	fr.f = f;
	wbx_create_host(&layout, "guest-dies-2.wbx", file_read, (uintptr_t)&fr, &r);
	fclose(f);
	CHECK(!r.error_message[0] && r.data != 0);
	mb_host *h = (mb_host *)r.data;
	if (h) {
		wbx_seal(h, &r);
		printf("run_guest: a guest dying while it is sealed: %s\n", r.error_message);
		CHECK(strstr(r.error_message, "died while sealing") != NULL && strstr(r.error_message, "crashed") != NULL);
		wbx_destroy_host(h, &r);
	}
	if (fails == 0) printf("run_guest: all checks passed\n");
	else printf("run_guest: %d checks FAILED\n", fails);
	return fails ? 1 : 0;
}

static int v3_flow(const char *guest, bool kit0) {
	mb_return r;
	typedef int (MB_GUEST_ABI *int_fn)(void);
	typedef uint64_t (MB_GUEST_ABI *u64_fn)(void);
	mb_host *h = make_v3_host(guest);
	STAGE("v3 host created + guest mounted");
	wbx_activate_host(h, &r);
	CHECK(((init_fn)proc(h, "Init"))() == 1);
	seal_and_activate(h);
	STAGE("v3 clock + sleeps + single wait");
	CHECK(((int_fn)proc(h, "V3ClockTicks"))() == 1);
	CHECK(((int_fn)proc(h, "V3NanosleepExact"))() == 1);
	CHECK(((int_fn)proc(h, "V3TimedWaitExpires"))() == 1);
	CHECK(((int_fn)proc(h, "V3WaitBitset"))() == 1);
	STAGE("v3 waiter order + ties");	CHECK(((int_fn)proc(h, "V3WaitOrder"))() == 1);
	STAGE("v3 an expired waiter leaves its queue");	CHECK(((int_fn)proc(h, "V3ExpiredWaiterLeavesTheQueue"))() == 1);
	STAGE("v3 thread exit while the rest wait timed");
	CHECK(((int_fn)proc(h, "V3ExitDuringTimedWait"))() == 1);
	STAGE("v3 memory + files");
	CHECK(((int_fn)proc(h, "V3MremapMoves"))() == 1);
	CHECK(((int_fn)proc(h, "V3HintHonored"))() == 1);
	CHECK(((int_fn)proc(h, "V3OTrunc"))() == 1);
	STAGE("v3 save/load across a timed wait");
	CHECK(((int_fn)proc(h, "SetupWaiter"))() == 1);
	uint64_t deadline = ((u64_fn)proc(h, "GetDeadline"))();
	membuf state = {0};
	wbx_deactivate_host(h, &r);
	wbx_save_state(h, mem_write, (uintptr_t)&state, &r);
	CHECK(!r.error_message[0]);
	/* v3 thread-state format: Se3 in (and the v2 body inside it) */
	CHECK(state_contains(&state, "GuestThreadSe3"));
	CHECK(state_contains(&state, "GuestThreadSet"));
	wbx_activate_host(h, &r);
	uint64_t o1 = ((u64_fn)proc(h, "ExpireStep"))();
	CHECK(o1 != 0);
	CHECK(o1 == deadline + 1000);   /* expired exactly at the deadline */
	state.pos = 0;
	wbx_deactivate_host(h, &r);
	wbx_load_state(h, mem_read, (uintptr_t)&state, &r);
	CHECK(!r.error_message[0]);
	wbx_activate_host(h, &r);
	uint64_t o2 = ((u64_fn)proc(h, "ExpireStep"))();
	CHECK(o2 == o1);                /* the wake happens at the same virtual time */
	/* Guest kit revision 2: a lone yield costs a tick, an expired wait gives
	 * way, and a sleep of the largest time there is saturates the clock
	 * instead of running it backwards. A guest built with no revision keeps
	 * the old answers. The sleep is last: the clock is spent after it. */
	STAGE("v3 kit revision 2: lone yields, expired waits, a huge sleep");
	const int want = kit0 ? 0 : 1;
	CHECK(((int_fn)proc(h, "V3LoneYield"))() == want);
	CHECK(((int_fn)proc(h, "V3ExpiredWaitYields"))() == want);
	CHECK(((int_fn)proc(h, "V3HugeSleep"))() == want);
	free(state.buf);
	wbx_deactivate_host(h, &r);
	wbx_destroy_host(h, &r);
	return fails != 0;
}

static void seal_and_activate(mb_host *h) {
	mb_return r;
	fprintf(stderr, "[stage] sealing\n"); fflush(stderr);
	wbx_deactivate_host(h, &r);
	wbx_seal(h, &r);
	if (r.error_message[0]) { fprintf(stderr, "seal: %s\n", r.error_message); exit(1); }
	wbx_activate_host(h, &r);
}

/* Stage markers on stderr, which is unbuffered: when the host aborts or the
 * process dies, buffered stdout is lost, and the last thing seen is whatever the
 * GUEST printed (its writes go through the host's stderr). That reads as "it
 * stopped right after guest init" no matter where it really stopped. */

/* A guest that never comes back from a call is stopped from another thread
 * (wbx_stop_guest, 2026-10-19), as a frontend's watchdog does: one spinning in
 * its own code (stopped by a signal on Linux, by being suspended and sent out
 * on Windows) and one spinning on system calls (stopped at the next one; on
 * Linux the stop's signal is blocked for it, or the signal would end it
 * between two calls and the check at a system call would go untested).
 * Each call comes back, the machine is dead, and the reason is the one given.
 * A stop asked for after a call ended by itself is cancelled and ends nothing.
 * The count of working system calls moves for getppid and not for a yield. */
struct stopper { mb_host *h; volatile int done; int asked; };
/* the callback the guest calls in the third part: asks for a stop from inside
 * the call, then (when told to) counts work it did for the guest, as a GPU
 * bridge does after a driver call */
static mb_host *g_stop_host;
static uint64_t g_frontend_work;
static int g_work_after_ask;
static uintptr_t MB_GUEST_ABI stop_cb(uintptr_t v, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t a6) {
	(void)v;(void)a2;(void)a3;(void)a4;(void)a5;(void)a6;
	/* static: a sysv function holding a 1 KiB local while it calls a win64
	 * one crashed mingw's GCC 13 ("internal compiler error: in
	 * choose_baseaddr") */
	static mb_return r;
	wbx_stop_guest(g_stop_host, "asked from inside a callback", &r);
	if (g_work_after_ask) g_frontend_work++;
	return 0;
}
static void sleep_ms(int ms) {
#ifdef _WIN32
	Sleep((DWORD)ms);
#else
	struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
	nanosleep(&ts, NULL);
#endif
}
#ifdef _WIN32
static DWORD WINAPI stopper_fn(LPVOID arg)
#else
static void *stopper_fn(void *arg)
#endif
{
	struct stopper *s = (struct stopper *)arg;
	sleep_ms(200);
	while (!s->done) {
		mb_return r;
		wbx_stop_guest(s->h, "stopped by the test after 200 ms", &r);
		s->asked++;
		sleep_ms(50);
	}
	return 0;
}

static void stop_from_callback(const char *guest) {
	/* A stop asked for while the guest is in host code waits for its next
	 * system call; one the guest worked past is dropped. Here the stop is
	 * asked inside a host callback, and the frontend's counted work after it
	 * (wbx_count_work_from) drops it: the call ends by itself. Without the
	 * work the guest dies at its first yield, with the reason given. */
	for (int worked = 1; worked >= 0; worked--) {
		typedef int (MB_GUEST_ABI *n_ret_fn)(int);
		typedef void (MB_GUEST_ABI *setcb_any)(uintptr_t);
		mb_host *h = make_host(guest, 0xABCD);
		mb_return r;
		wbx_activate_host(h, &r);
		CHECK(((init_fn)proc(h, "Init"))() == 1);
		wbx_stop_from_here(h, &r);
		wbx_count_work_from(h, &g_frontend_work, &r);
		g_stop_host = h;
		g_work_after_ask = worked;
		wbx_get_callback_addr(h, stop_cb, 0, &r);
		((setcb_any)proc(h, "SetLogCallback"))(r.data);
		const int got = ((n_ret_fn)proc(h, "CallHostThenYield"))(100);
		char why[512];
		wbx_get_death(h, why, sizeof why, &r);
		printf("run_guest: a stop asked from a callback, %s: came back with %d, dead=%d%s%s\n",
		       worked ? "with work after it" : "with no work after it", got, (int)r.data,
		       r.data ? ": " : "", r.data ? why : "");
		if (worked) CHECK(got == 1 && r.data == 0);
		else CHECK(got == 0 && r.data == 1 && strstr(why, "asked from inside a callback") != NULL);
		wbx_stop_cancel(h, &r);
		wbx_count_work_from(h, NULL, &r);
		wbx_deactivate_host(h, &r);
		wbx_destroy_host(h, &r);
	}
}

static int stop_flow(const char *guest) {
	typedef int (MB_GUEST_ABI *int_fn)(void);
	typedef void (MB_GUEST_ABI *n_fn)(int);
	const char *const spins[2] = { "SpinForever", "SpinOnSyscalls" };
	for (int k = 0; k < 2; k++) {
		mb_host *h = make_host(guest, 0xABCD);
		mb_return r;
		wbx_activate_host(h, &r);
		CHECK(((init_fn)proc(h, "Init"))() == 1);
		if (k == 0) {
			wbx_guest_activity(h, &r);
			const uint64_t before = (uint64_t)r.data;
			((n_fn)proc(h, "Yield"))(1000);
			wbx_guest_activity(h, &r);
			const uint64_t yielded = (uint64_t)r.data;
			((n_fn)proc(h, "Work"))(1000);
			wbx_guest_activity(h, &r);
			printf("run_guest: working calls counted: %llu before, %llu after 1000 yields, %llu after 1000 getppid\n",
			       (unsigned long long)before, (unsigned long long)yielded, (unsigned long long)r.data);
			CHECK(yielded == before && (uint64_t)r.data == before + 1000);
		}
		/* a stop asked for before any call, then cancelled, ends nothing */
		wbx_stop_from_here(h, &r);
		wbx_stop_cancel(h, &r);
		CHECK(((init_fn)proc(h, "Init"))() == 1);
		struct stopper s = { h, 0, 0 };
#ifdef _WIN32
		HANDLE t = CreateThread(NULL, 0, stopper_fn, &s, 0, NULL);
#else
		pthread_t t;
		pthread_create(&t, NULL, stopper_fn, &s);
#endif
#ifndef _WIN32
		sigset_t stop_sig, was;
		sigemptyset(&stop_sig);
		sigaddset(&stop_sig, MB_STOP_SIGNAL);
		if (k == 1) pthread_sigmask(SIG_BLOCK, &stop_sig, &was);
#endif
		const int got = ((int_fn)proc(h, spins[k]))();
#ifndef _WIN32
		if (k == 1) pthread_sigmask(SIG_SETMASK, &was, NULL);
#endif
		s.done = 1;
#ifdef _WIN32
		WaitForSingleObject(t, INFINITE);
		CloseHandle(t);
#else
		pthread_join(t, NULL);
#endif
		char why[512];
		wbx_get_death(h, why, sizeof why, &r);
		printf("run_guest: %s came back with %d, dead=%d, after %d asks: %s\n", spins[k], got, (int)r.data, s.asked, why);
		CHECK(got == 0 && r.data == 1 && strstr(why, "stopped by the test after 200 ms") != NULL);
		wbx_deactivate_host(h, &r);
		wbx_destroy_host(h, &r);
	}
	stop_from_callback(guest);
	if (fails == 0) printf("run_guest: all checks passed\n");
	else printf("run_guest: %d checks FAILED\n", fails);
	return fails ? 1 : 0;
}

/* The child half of the abort check: make a host, let the guest abort. The call
 * comes back - the machine is dead, the process is not - and the child says so
 * by its exit status. A child still, so that MINIBOX_LOG names a fresh file. */
static int abort_child(const char *guest) {
	mb_return r;
	mb_host *h = make_host(guest, 0xABCD);
	wbx_activate_host(h, &r);
	typedef void (MB_GUEST_ABI *abort_fn)(void);
	((abort_fn)proc(h, "Abort"))();
	char why[256];
	wbx_get_death(h, why, sizeof why, &r);
	return r.data == 1 ? 0 : 3;
}

#ifndef _WIN32
#include <setjmp.h>
#include <signal.h>
/* The child half of the host-fault check: a SIGSEGV handler of the process's
 * own is installed FIRST, the way a runtime's is (Mono turns such faults into
 * exceptions), then a host is made - which puts tripguard in front of it - and
 * host code reads through a null pointer. tripguard must pass it on; the
 * process's handler recovers; the child exits 0. */
static sigjmp_buf g_host_fault_env;
static void host_fault_handler(int sig) { (void)sig; siglongjmp(g_host_fault_env, 1); }
static int host_fault_child(const char *guest) {
	mb_return r;
	signal(SIGSEGV, host_fault_handler);
	mb_host *h = make_host(guest, 0xABCD);
	wbx_activate_host(h, &r);
	if (sigsetjmp(g_host_fault_env, 1) == 0) {
		volatile uintptr_t nowhere = 0x20;
		volatile uint32_t v = *(volatile uint32_t *)nowhere;
		(void)v;
		return 3;   /* the read did not fault */
	}
	return 0;       /* it faulted, was passed on, and this process handled it */
}

/* A fault in HOST code is not the guest's, and miniBox cannot know whether the
 * process will handle it - so the log must say it was passed on, not call it
 * unhandled (issue #82: a handled exception read as four crashes). */
static int host_fault_is_reported_as_passed_on(const char *self, const char *guest) {
	const char *dir = getenv("TMPDIR");
	if (dir == NULL || dir[0] == '\0') dir = "/tmp";
	char log[512], cmd[2048];
	snprintf(log, sizeof log, "%s/run_guest_hostfault_%ld_%ld.log", dir, (long)getpid(), (long)time(NULL));
	remove(log);
	setenv("MINIBOX_LOG", log, 1);
	snprintf(cmd, sizeof cmd, "'%s' --host-fault-child '%s' >/dev/null 2>&1", self, guest);
	int status = system(cmd);
	unsetenv("MINIBOX_LOG");
	static char text[64 * 1024];
	size_t n = 0;
	FILE *f = fopen(log, "rb");
	if (f != NULL) { n = fread(text, 1, sizeof text - 1, f); fclose(f); }
	text[n] = '\0';
	remove(log);
	const bool survived = status == 0;
	const bool passed_on = strstr(text, "fault in host code, passed on") != NULL;
	const bool not_unhandled = strstr(text, "unhandled fault") == NULL;
	printf("run_guest: host fault child survived=%d, log says passed on=%d, log avoids \"unhandled\"=%d\n",
	       survived, passed_on, not_unhandled);
	return survived && passed_on && not_unhandled;
}
#endif

#ifdef _WIN32
#include <windows.h>
/* The child half of the handler-recursion check (chimera#127).
 *
 * A vectored handler that faults is called again FOR ITS OWN FAULT, with no
 * depth limit and no second chance. The layout pointer is put somewhere that
 * cannot be read - which is exactly what a destroyed host used to leave behind -
 * and then host code faults. The handler starts to describe that fault, reads
 * the layout, and faults itself. Unguarded, that is an endless tower of
 * handlers on one stack and the process dies of a stack overflow with neither
 * fault named anywhere; guarded, the second fault is said once and passed on,
 * and the log still names the first. The log is the verdict - the child dies
 * either way, and only what it managed to say differs. */
static int handler_recursion_child(const char *guest) {
	mb_return r;
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
	mb_host *h = make_host(guest, 0xABCD);
	wbx_activate_host(h, &r);
	mb_tripguard_set_layout((const mb_layout *)(uintptr_t)0x40);
	volatile uint32_t v = *(volatile uint32_t *)(uintptr_t)0x20;
	(void)v;
	return 3;   /* the read did not fault */
}

/* The parent half: the handler must say the first fault once, notice that it
 * faulted on its own diagnosis, and stop - not repeat itself until the stack
 * is gone. An unguarded handler writes the same line hundreds of times and
 * never writes the second sentence at all. */
static int handler_does_not_recurse(const char *self, const char *guest) {
	const char *dir = getenv("TEMP");
	if (dir == NULL || dir[0] == '\0') dir = ".";
	char log[512], cmd[2048];
	snprintf(log, sizeof log, "%s\\run_guest_recursion_%ld_%ld.log", dir, (long)getpid(), (long)time(NULL));
	remove(log);
	_putenv_s("MINIBOX_LOG", log);
	snprintf(cmd, sizeof cmd, "\"\"%s\" --handler-recursion-child \"%s\" >NUL 2>&1\"", self, guest);
	system(cmd);
	_putenv_s("MINIBOX_LOG", "");
	static char text[256 * 1024];
	size_t n = 0;
	FILE *f = fopen(log, "rb");
	if (f != NULL) { n = fread(text, 1, sizeof text - 1, f); fclose(f); }
	text[n] = '\0';
	remove(log);
	int veh_lines = 0;
	for (const char *p = text; (p = strstr(p, "[veh] ")) != NULL; p += 6) veh_lines++;
	const bool said_once = strstr(text, "the fault handler faulted while reporting a fault") != NULL;
	const bool first_named = strstr(text, "fault in host code, passed on") != NULL;
	const bool bounded = veh_lines <= 4;
	printf("run_guest: handler-recursion child: first fault named=%d, own fault said=%d, [veh] lines=%d (bounded=%d)\n",
	       first_named, said_once, veh_lines, bounded);
	return first_named && said_once && bounded;
}
#endif

#if !defined(_WIN32) && defined(__x86_64__)   /* %fs repair: x86-64 only (aarch64 never loses TPIDR_EL0) */
/* Can this machine run a real guest-side drop (guest WRFSBASE(0))? Some
 * kernels (WSL2) kill it despite the CPU flag - and the base is already 0
 * when the fault arrives, so nothing libc may run until %fs is put back.
 * Probed INLINE, not forked: forked children observably survive it here
 * while the real path dies, so a fork probe would lie. Saves the live base
 * with rdfsbase and restores it with a RAW arch_prctl (no libc call
 * survives %fs = 0, not even the signal restore). */
#include <sys/prctl.h>
#ifndef ARCH_SET_FS
#define ARCH_SET_FS 0x1002
#endif
static uintptr_t probe_live_fs;
static sigjmp_buf probe_env;
static volatile int probe_faulted;
static void probe_restore_fs(void) {
	__asm__ volatile ("mov $158, %%rax\n\t"   /* __NR_arch_prctl */
	                  "mov %1, %%rdi\n\t"
	                  "mov %0, %%rsi\n\t"
	                  "syscall"
	                  :: "r" (probe_live_fs), "i" (ARCH_SET_FS)
	                  : "rax", "rdi", "rsi", "rcx", "r11", "memory");
}
static void probe_died(int sig) {
	(void)sig;
	probe_faulted = 1;
	probe_restore_fs();
	siglongjmp(probe_env, 1);
}
static bool guest_wrfsbase0_works(void) {
	__asm__ volatile ("rdfsbase %0" : "=r" (probe_live_fs) :: "memory");
	struct sigaction sa, old_segv, old_ill;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = probe_died;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGSEGV, &sa, &old_segv);
	sigaction(SIGILL, &sa, &old_ill);
	bool ok = true;
	probe_faulted = 0;
	if (sigsetjmp(probe_env, 1) == 0) {
		__asm__ volatile ("wrfsbase %0" :: "r" (0ul) : "memory");
	}
	/* A fault anywhere in there means this kernel cannot do a guest-side
	 * drop, even if the write itself went through: the repair under test
	 * needs the fault it causes, delivered cleanly. */
	ok = !probe_faulted;
	probe_restore_fs();
	sigaction(SIGSEGV, &old_segv, NULL);
	sigaction(SIGILL, &old_ill, NULL);
	return ok;
}

/* The child half of the dropped-%fs check: what Windows does to the base at
 * every scheduler quantum - the base reads 0 at a %fs access mid-guest, with
 * the entry-parked host base still valid to check against. A fault in guest
 * code must reinstall the live thread pointer and retry (once), even though
 * this guest carries no PT_TLS and the host never swaps; the host's own base
 * and the value read must be identical before and after. Then a genuine fault
 * (WildWrite) must still kill the machine.
 * Linux-only: the drop it simulates cannot happen here. */
static int fs_repair_child(const char *guest) {
	mb_return r;
	if (!guest_wrfsbase0_works()) {
		fprintf(stderr, "[fsrepair] SKIP: this kernel kills WRFSBASE(0); "
		                "the test needs a real guest-side drop\n");
		return 0;
	}
	mb_host *h = make_host(guest, 0xABCD);
	wbx_activate_host(h, &r);
	typedef uint64_t (MB_GUEST_ABI *u64_fn)(void);
	typedef uint32_t (MB_GUEST_ABI *alive_fn)(void);
	typedef void (MB_GUEST_ABI *void_fn)(void);
	u64_fn FsProbe = (u64_fn)proc(h, "FsProbe");
	u64_fn ClobberAndProbe = (u64_fn)proc(h, "ClobberAndProbe");
	alive_fn Alive = (alive_fn)proc(h, "Alive");
	uint64_t v1 = FsProbe();
	CHECK(v1 != 0);
	const uintptr_t f0 = host_fs_base();
	CHECK(f0 != 0);
	uint64_t v2 = ClobberAndProbe();
	CHECK(Alive() == 0xA11FE);   /* survived: without the repair this is refused (0) */
	/* and what the retried access read is what this guest saw before the
	 * drop - the host's base, because it does not own %fs. Its thread
	 * pointer here would leave the host's C reading glibc's thread locals
	 * out of the guest's block for the rest of the call. */
	CHECK(v2 == v1);
	uint64_t v3 = FsProbe();
	CHECK(v3 == v1);             /* the host base, intact across the episode */
	CHECK(host_fs_base() == f0); /* ...in the register too */
	fprintf(stderr, "[fsrepair] v1=%llx v2=%llx v3=%llx\n",
	        (unsigned long long)v1, (unsigned long long)v2, (unsigned long long)v3);
	void *p = malloc(1024); CHECK(p != NULL); free(p);   /* host TLS works */
	((void_fn)proc(h, "WildWrite"))();
	char why[512];
	wbx_get_death(h, why, sizeof why, &r);
	CHECK(r.data == 1);
	CHECK(Alive() == 0);   /* refused: a genuine fault still kills */
	wbx_destroy_host(h, &r);
	return fails != 0;
}
#endif

/* A guest that aborts must leave its reason in the diagnostic log: the death
 * named as an abort, and what the guest last wrote to stderr. */
static int guest_abort_is_reported(const char *self, const char *guest) {
#ifdef _WIN32
	(void)self; (void)guest;
	printf("run_guest: abort report not checked on Windows (a crashing child raises Windows Error Reporting)\n");
	return 1;
#else
	const char *dir = getenv("TMPDIR");
	if (dir == NULL || dir[0] == '\0') dir = "/tmp";
	char log[512], cmd[2048];
	snprintf(log, sizeof log, "%s/run_guest_abort_%ld_%ld.log", dir, (long)getpid(), (long)time(NULL));
	remove(log);
	setenv("MINIBOX_LOG", log, 1);
	snprintf(cmd, sizeof cmd, "'%s' --abort-child '%s' >/dev/null 2>&1", self, guest);
	int status = system(cmd);
	unsetenv("MINIBOX_LOG");
	static char text[64 * 1024];
	size_t n = 0;
	FILE *f = fopen(log, "rb");
	if (f != NULL) { n = fread(text, 1, sizeof text - 1, f); fclose(f); }
	text[n] = '\0';
	remove(log);
	const bool survived = status == 0;
	const bool named = strstr(text, "the core aborted") != NULL;
	const bool words = strstr(text, "conformance guest: these are my last words") != NULL;
	/* and where it was: the abort's frames, in the form addr2line takes */
	const bool stack = strstr(text, "guest stack (addr2line -f -C -e core.wbx): +") != NULL;
	printf("run_guest: abort child survived=%d, log names the abort=%d, log has the guest's words=%d, and its stack=%d\n", survived, named, words, stack);
	return survived && named && words && stack;
#endif
}

/* A guest that dies - in every way the conformance guest knows - hands control
 * back. The call returns; the machine says why; every later call is refused and
 * runs nothing; and a state load brings back exactly the machine that was saved,
 * which the step after it proves. One host, killed and revived again and again. */
#ifdef _WIN32
/* chimera#166: out of memory is said as that. Windows refusing to commit the
 * machine's memory (the system at its commit limit) used to leave the pages
 * marked committed; the guest's next write to them faulted, was reported as
 * "the core crashed", and going back to a safe frame crashed again. Now the
 * refused pages are committed on the guest's fault, a refusal there is the
 * machine's death as "out of memory", and once memory is back a load revives
 * it and the same memory works. Only a machine over 4 GiB is committed lazily
 * (pal_win.c), so this one is. */
static void out_of_memory_is_said(const char *path) {
	typedef uint32_t (MB_GUEST_ABI *touch_fn)(void);
	mb_return r;
	FILE *f = fopen(path, "rb");
	if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
	mb_memory_layout_template layout = {
		.sbrk_size = 16u<<20, .sealed_size = 16u<<20, .invis_size = 16u<<20,
		.plain_size = 16u<<20, .mmap_size = ((uintptr_t)4 << 30) + (32u<<20),
	};
	freader fr = { f };
	wbx_create_host(&layout, "guest.wbx", file_read, (uintptr_t)&fr, &r);
	fclose(f);
	CHECK(!r.error_message[0]);
	mb_host *h = (mb_host *)r.data;
	uint32_t seed = 0xBEEF;
	memreader mr = { (const uint8_t *)&seed, sizeof(seed), 0 };
	wbx_mount_file(h, "seed", mem_reader, (uintptr_t)&mr, false, &r);
	wbx_activate_host(h, &r);
	((setcb_fn)proc(h, "SetLogCallback"))(0);
	CHECK(((init_fn)proc(h, "Init"))() == 1);
	seal_and_activate(h);
	touch_fn TouchFresh = (touch_fn)proc(h, "TouchFresh");

	membuf state = {0};
	wbx_deactivate_host(h, &r);
	wbx_save_state(h, mem_write, (uintptr_t)&state, &r);
	CHECK(!r.error_message[0]);
	wbx_activate_host(h, &r);

	STAGE("a guest whose memory Windows will not commit");
	SetEnvironmentVariableA("MB_REFUSE_COMMITS", "1");
	TouchFresh();
	SetEnvironmentVariableA("MB_REFUSE_COMMITS", NULL);
	char why[512];
	wbx_get_death(h, why, sizeof why, &r);
	printf("run_guest: out of memory -> dead=%llu: %s\n", (unsigned long long)r.data, why);
	CHECK(r.data == 1);
	CHECK(strstr(why, "out of memory") != NULL);
	CHECK(strstr(why, "crashed") == NULL);

	STAGE("memory back: the machine revives, and the same memory works");
	state.pos = 0;
	wbx_deactivate_host(h, &r);
	wbx_load_state(h, mem_read, (uintptr_t)&state, &r);
	CHECK(!r.error_message[0]);
	wbx_activate_host(h, &r);
	CHECK(TouchFresh() == 0xF4E5);
	wbx_destroy_host(h, &r);
	free(state.buf);
}
#endif

static void guest_deaths_are_survived(const char *path) {
	typedef void (MB_GUEST_ABI *void_fn)(void);
	typedef uint32_t (MB_GUEST_ABI *alive_fn)(void);
	mb_return r;
	mb_host *h = make_host(path, 0xABCD);
	wbx_activate_host(h, &r);
	((setcb_fn)proc(h, "SetLogCallback"))(0);
	CHECK(((init_fn)proc(h, "Init"))() == 1);
	seal_and_activate(h);
	alive_fn Alive = (alive_fn)proc(h, "Alive");
	step_fn Step = (step_fn)proc(h, "Step");
	CHECK(Alive() == 0xA11FE);

	membuf state = {0};
	wbx_deactivate_host(h, &r);
	wbx_save_state(h, mem_write, (uintptr_t)&state, &r);
	CHECK(!r.error_message[0]);
	wbx_activate_host(h, &r);
	const uint32_t expected = Step(0x5555);   /* what the saved machine does next */
#ifndef _WIN32
	const uintptr_t fs_before_deaths = host_fs_base();
#endif

	static const struct { const char *name; const char *says; } deaths[] = {
		{ "Abort", "aborted" },
		{ "Halt", "stopped itself" },
		{ "Ud2", "illegal instruction" },
#if defined(__x86_64__)   /* aarch64 integer division by zero does not trap: it answers 0 */
		{ "DivideByZero", "divided by zero" },
#endif
		{ "WildWrite", "crashed" },
		{ "ExitNow", "exited (status 7)" },
		{ "UnknownSyscall", "system call 4242" },
		{ "Deadlock", "deadlock" },
		{ "CallNull", "crashed" },
		{ "CallWild", "crashed" },
		{ "CallUnregisteredSlot", "never registered" },
#ifndef _WIN32
		/* Linux-only: faulting with rsp in a guard page needs the fault
		 * handler on an alternate signal stack to report anything at all.
		 * VEH has no altstack - the nested fault takes the process with no
		 * report - so this cannot pass on Windows by construction. */
		{ "GuardFault", "illegal instruction" },
#endif
	};
	char why[512];
	for (size_t i = 0; i < sizeof deaths / sizeof deaths[0]; i++) {
		STAGE("a guest that dies: %s", deaths[i].name);
		wbx_get_death(h, why, sizeof why, &r);
		CHECK(r.data == 0 && why[0] == '\0');
		((void_fn)proc(h, deaths[i].name))();
		wbx_get_death(h, why, sizeof why, &r);
		printf("run_guest: %s -> dead=%llu: %s\n", deaths[i].name, (unsigned long long)r.data, why);
		CHECK(r.data == 1);
		CHECK(strstr(why, deaths[i].says) != NULL);
		/* the dying call's own words, and nobody else's: Abort says something
		 * first, the others say nothing - and Init's lines are not theirs */
		if (strcmp(deaths[i].name, "Abort") == 0) CHECK(strstr(why, "these are my last words") != NULL);
		else CHECK(strstr(why, "It said") == NULL);
		CHECK(strstr(why, "Init done") == NULL);
		CHECK(Alive() == 0);   /* refused: nothing runs in a dead machine */

		state.pos = 0;
		wbx_deactivate_host(h, &r);
		wbx_load_state(h, mem_read, (uintptr_t)&state, &r);
		CHECK(!r.error_message[0]);
		wbx_activate_host(h, &r);
		wbx_get_death(h, why, sizeof why, &r);
		CHECK(r.data == 0 && why[0] == '\0');
		CHECK(Alive() == 0xA11FE);
		CHECK(Step(0x5555) == expected);   /* the machine that was saved, exactly */
#ifndef _WIN32
		CHECK(host_fs_base() == fs_before_deaths);   /* and the host's thread pointer, untouched */
#endif
	}
#ifndef _WIN32
	/* The OS refusing the protection change a tracked write needs (on Linux,
	 * past vm.max_map_count) is the guest's death with that reason, not a trap
	 * with no word (2026-10-18). Through the test hook: one refusal. */
	{
		extern int mb_pal_protect_refusals;
		typedef uint32_t (MB_GUEST_ABI *u32_fn)(void);
		mb_pal_protect_refusals = 1;
		((u32_fn)proc(h, "WriteCleanPage"))();
		mb_pal_protect_refusals = 0;
		wbx_get_death(h, why, sizeof why, &r);
		printf("run_guest: a protection change refused -> dead=%llu: %s\n", (unsigned long long)r.data, why);
		CHECK(r.data == 1 && strstr(why, "refused a memory protection change") != NULL);
		state.pos = 0;
		wbx_deactivate_host(h, &r);
		wbx_load_state(h, mem_read, (uintptr_t)&state, &r);
		CHECK(!r.error_message[0]);
		wbx_activate_host(h, &r);
		CHECK(((u32_fn)proc(h, "WriteCleanPage"))() == 1);   /* and the write goes ahead now */
	}
#endif
	wbx_deactivate_host(h, &r);
	wbx_destroy_host(h, &r);
	free(state.buf);
}

int main(int argc, char **argv) {
	if (argc > 2 && strcmp(argv[1], "--abort-child") == 0) return abort_child(argv[2]);
	if (argc > 2 && strcmp(argv[1], "--stop") == 0) return stop_flow(argv[2]);
#ifndef _WIN32
	if (argc > 2 && strcmp(argv[1], "--host-fault-child") == 0) return host_fault_child(argv[2]);
#if defined(__x86_64__)
	if (argc > 2 && strcmp(argv[1], "--fs-repair-child") == 0) return fs_repair_child(argv[2]);
#endif
#else
	if (argc > 2 && strcmp(argv[1], "--handler-recursion-child") == 0) return handler_recursion_child(argv[2]);
#endif
	if (argc > 2 && strcmp(argv[1], "--v3") == 0) return v3_flow(argv[2], false);
	if (argc > 2 && strcmp(argv[1], "--v3-kit0") == 0) return v3_flow(argv[2], true);
	if (argc > 3 && strcmp(argv[1], "--dies") == 0) return dies_starting_or_sealing(argv[2], argv[3]);
	if (argc > 2 && strcmp(argv[1], "--probe-off") == 0) {
		/* Probe forced off before anything initializes: the FSGSBASE
		 * instructions must be unreachable, so the whole standard flow
		 * below has to pass without them. Cross-platform (the Windows
		 * suite runs this too). */
#ifdef _WIN32
		_putenv_s("MB_NO_FSGSBASE", "1");
#else
		setenv("MB_NO_FSGSBASE", "1", 1);
#endif
		assert(!mb_fsbase_ok());
		assert(!mb_fs_swap);
		argv[1] = argv[2]; argc--;   /* consume the flag; argv[0] stays self */
	}
	/* --kit0: the guest was built with a kit of no revision, and must get
	 * the answers cores built before revision 1 got */
	bool kit0 = false;
	if (argc > 2 && strcmp(argv[1], "--kit0") == 0) {
		kit0 = true;
		argv[1] = argv[2]; argc--;
	}
	const char *path = argc > 1 ? argv[1] : "guest.wbx";
	mb_return r;

	setvbuf(stdout, NULL, _IONBF, 0);
	STAGE("start, guest=%s", path);

	/* ---- main run: init, callback, seal, steps, savestate round-trip ---- */
	mb_host *h = make_host(path, 0xABCD);
	STAGE("host created + guest mounted");
	wbx_activate_host(h, &r);
	STAGE("activated");

	STAGE("resolving guest exports");
	init_fn Init = (init_fn)proc(h, "Init");
	step_fn Step = (step_fn)proc(h, "Step");
	getacc_fn GetAcc = (getacc_fn)proc(h, "GetAcc");
	setcb_fn SetLogCallback = (setcb_fn)proc(h, "SetLogCallback");

	/* register a host callback in slot 0 and hand its guest-visible thunk over */
	wbx_get_callback_addr(h, log_cb, 0, &r);
	CHECK(!r.error_message[0]);
	SetLogCallback(r.data);

	STAGE("calling guest Init");
	CHECK(Init() == 1);

	/* nothing of the host's may be left in the guest's r10: not on entering an
	 * export, not after a syscall returns (see interop_bin.c) */
	{
		typedef uint64_t (MB_GUEST_ABI *u64_fn)(void);
		uint64_t at_entry = ((u64_fn)proc(h, "EntryR10"))();
		uint64_t after_syscall = ((u64_fn)proc(h, "SyscallR10"))();
		uint64_t after_extcall = ((u64_fn)proc(h, "ExtcallR10"))();
		printf("run_guest: r10 seen by the guest on entry=%llx, after a syscall=%llx, "
		       "after a callback=%llx\n", (unsigned long long)at_entry,
		       (unsigned long long)after_syscall, (unsigned long long)after_extcall);
		CHECK(at_entry == 0);
		CHECK(after_syscall == 0);
		CHECK(after_extcall == 0);
	}
	/* nor in its xmm0-15. Before the entry case this side fills xmm0-5 (scratch
	 * in both host ABIs) with ones, so the check does not rest on whatever the
	 * host's own code happened to leave there. On aarch64 it fills v0-v31,
	 * d8-d15 included (the compiler keeps this function's own around the
	 * asm): the blob must clear those on entry too. */
	{
		typedef uint64_t (MB_GUEST_ABI *u64_fn)(void);
		const u64_fn entry = (u64_fn)proc(h, "EntryXmm");
#if defined(__aarch64__)
		__asm__ volatile(".irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31\n\t"
		                 "movi v\\n\\().2d, #0xffffffffffffffff\n\t"
		                 ".endr"
		                 ::: "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11",
		                     "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22",
		                     "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31");
		const char *vregs = "v0-v31";
#elif defined(__x86_64__)
		__asm__ volatile("pcmpeqd %%xmm0, %%xmm0\n\tpcmpeqd %%xmm1, %%xmm1\n\tpcmpeqd %%xmm2, %%xmm2\n\t"
		                 "pcmpeqd %%xmm3, %%xmm3\n\tpcmpeqd %%xmm4, %%xmm4\n\tpcmpeqd %%xmm5, %%xmm5"
		                 ::: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5");
		const char *vregs = "xmm0-15";
#else
#error "miniBox runs on x86-64 and aarch64 only"
#endif
		uint64_t at_entry = entry();
		uint64_t after_syscall = ((u64_fn)proc(h, "SyscallXmm"))();
		uint64_t after_extcall = ((u64_fn)proc(h, "ExtcallXmm"))();
		printf("run_guest: %s seen by the guest on entry=%llx, after a syscall=%llx, "
		       "after a callback=%llx\n", vregs, (unsigned long long)at_entry,
		       (unsigned long long)after_syscall, (unsigned long long)after_extcall);
		CHECK(at_entry == 0);
		CHECK(after_syscall == 0);
		CHECK(after_extcall == 0);
	}
	/* The floating-point control words are the guest's own (mb_context,
	 * 2026-10-18). This host runs at Windows' default 53-bit x87 precision (0x27F)
	 * with round-toward-zero SSE rounding, and the guest still starts from
	 * 0x37F/0x1F80; what the guest sets (round down, both units) stays with
	 * it across calls, a syscall and a callback; the host gets its own back
	 * after every call, and has them inside the callback. On aarch64 the same
	 * with FPCR: the host rounds toward zero, the guest starts at 0 (to
	 * nearest) and sets round down. */
	{
		typedef uint64_t (MB_GUEST_ABI *u64_fn)(void);
		typedef void (MB_GUEST_ABI *fpuset_fn)(uint32_t, uint32_t);
		uint16_t keep_cw, cw; uint32_t keep_mx, mx;
		host_fpu_get(&keep_cw, &keep_mx);
		const uint16_t host_cw = FPU_HOST_CW; const uint32_t host_mx = FPU_HOST_MX;
		const uint16_t guest_cw = FPU_GUEST_CW; const uint32_t guest_mx = FPU_GUEST_MX;   /* round down */
		host_fpu_set(host_cw, host_mx);
		uint64_t seen = ((u64_fn)proc(h, "FpuSeen"))();
		host_fpu_get(&cw, &mx);
		printf("run_guest: control words the guest starts with %llx/%llx (host %x/%x)\n",
		       (unsigned long long)(seen >> 32), (unsigned long long)(uint32_t)seen, (unsigned)host_cw, (unsigned)host_mx);
		CHECK((seen >> 32) == FPU_START_CW && ((uint32_t)seen & ~FPU_FLAGS) == FPU_START_MX);
		CHECK(cw == host_cw && (mx & ~FPU_FLAGS) == host_mx);
		seen = ((u64_fn)proc(h, "FpuAtStart"))();
		printf("run_guest: the guest's start-up code ran with %llx/%llx\n",
		       (unsigned long long)(seen >> 32), (unsigned long long)(uint32_t)seen);
		CHECK((seen >> 32) == FPU_START_CW && ((uint32_t)seen & ~FPU_FLAGS) == FPU_START_MX);
		((fpuset_fn)proc(h, "FpuSet"))(guest_cw, guest_mx);
		host_fpu_get(&cw, &mx);
		CHECK(cw == host_cw && (mx & ~FPU_FLAGS) == host_mx);      /* the guest's stay in */
		seen = ((u64_fn)proc(h, "FpuSeen"))();
		CHECK((seen >> 32) == guest_cw && ((uint32_t)seen & ~FPU_FLAGS) == guest_mx);
		seen = ((u64_fn)proc(h, "FpuAfterSyscall"))();
		CHECK((seen >> 32) == guest_cw && ((uint32_t)seen & ~FPU_FLAGS) == guest_mx);
		g_cb_fcw = 0; g_cb_mxcsr = 0;
		seen = ((u64_fn)proc(h, "FpuAfterCallback"))();
		printf("run_guest: a host callback ran with %x/%x, the guest after it %llx/%llx\n",
		       (unsigned)g_cb_fcw, (unsigned)g_cb_mxcsr, (unsigned long long)(seen >> 32), (unsigned long long)(uint32_t)seen);
		CHECK(g_cb_fcw == host_cw && (g_cb_mxcsr & ~FPU_FLAGS) == host_mx);
		CHECK((seen >> 32) == guest_cw && ((uint32_t)seen & ~FPU_FLAGS) == guest_mx);
		((fpuset_fn)proc(h, "FpuSet"))(FPU_START_CW, FPU_START_MX);
		host_fpu_set(keep_cw, keep_mx);
	}
	/* calls that used to stop the machine (spec v2.2): each must answer
	 * and leave the machine alive. */
	{
		typedef int (MB_GUEST_ABI *int_fn)(void);
		CHECK(((int_fn)proc(h, "SigactionAccepted"))() == 1);
		CHECK(((int_fn)proc(h, "AnswersAreWritten"))() == 1);
		CHECK(((int_fn)proc(h, "CancellableCallKeepsItsArguments"))() == 1);
		typedef uint64_t (MB_GUEST_ABI *u64_fn)(void);
		CHECK(((u64_fn)proc(h, "CalleeSavedOnEntry"))() == 0);
		CHECK(((int_fn)proc(h, "UnalignedLengthsRoundUp"))() == 1);
#if defined(__x86_64__)   /* aarch64 has no direction flag */
		CHECK(((int_fn)proc(h, "ReturnsBackwards"))() == 1);
		{
			uint64_t flags;
			__asm__ volatile("pushfq\n\tpopq %0" : "=r"(flags));
			CHECK((flags & 0x400) == 0);   /* DF */
		}
#endif
		CHECK(((int_fn)proc(h, "PipeRefused"))() == 1);
		CHECK(((int_fn)proc(h, "GetrusageZeroed"))() == 1);
		CHECK(((int_fn)proc(h, "NullCloneRefused"))() == 1);
		CHECK(((int_fn)proc(h, "PwriteBadDescriptor"))() == 1);
		CHECK(((int_fn)proc(h, "SocketRefused"))() == 1);
		/* sysinfo by the guest kit's revision: this guest is built with the
		 * current kit unless the runner was told it was not */
		CHECK(((int_fn)proc(h, "SysinfoAnswer"))() == (kit0 ? 0 : 1));
		/* and the file answers: Linux's from kit revision 2 */
		const int files = ((int_fn)proc(h, "FileAnswers"))();
		if (files != (kit0 ? 0 : 2)) printf("run_guest: FileAnswers -> %d\n", files);
		CHECK(files == (kit0 ? 0 : 2));
	}
	/* spec v2 invariants a v3 host must preserve: this guest declares
	 * nothing, so the clock is constant, timeouts never expire on their
	 * own, and a blocked mremap is EEXIST. */
	{
		typedef int (MB_GUEST_ABI *int_fn)(void);
		CHECK(((int_fn)proc(h, "V2ClockConstant"))() == 1);
		CHECK(((int_fn)proc(h, "V2TimedWaitIgnored"))() == 1);
		CHECK(((int_fn)proc(h, "V2MremapBlocked"))() == 1);
	}
	STAGE("Init returned");
	seal_and_activate(h);

	STAGE("stepping the guest");
#ifndef _WIN32
	/* The first steps after the seal write to clean pages, so they take the
	 * dirty-page faults. This guest is C: its thread pointer is not in %fs, and
	 * the handler must leave the host's there - it once "repaired" it to the
	 * guest's, and the frontend's runtime broke a few calls later. */
	const uintptr_t fs_before_steps = host_fs_base();
#endif
	uint32_t s1 = Step(0x11111111);
	uint32_t s2 = Step(0x22222222);
#ifndef _WIN32
	printf("run_guest: host %%fs across faulting steps: before=%llx after=%llx\n",
	       (unsigned long long)fs_before_steps, (unsigned long long)host_fs_base());
	CHECK(host_fs_base() == fs_before_steps);
#endif
	STAGE("steps done");
	uint64_t acc_at_save = GetAcc();
	CHECK(g_last_log == (uint32_t)acc_at_save);   /* the guest->host callback fired */

	membuf state = {0};
	wbx_deactivate_host(h, &r);
	wbx_save_state(h, mem_write, (uintptr_t)&state, &r);
	CHECK(!r.error_message[0]);
	/* v2 thread-state format, byte for byte: GuestThreadSet in, Se3 never */
	CHECK(state_contains(&state, "GuestThreadSet"));
	CHECK(!state_contains(&state, "GuestThreadSe3"));
	wbx_activate_host(h, &r);

	uint32_t s3 = Step(0x33333333);
	CHECK(GetAcc() != acc_at_save);

	state.pos = 0;
	wbx_deactivate_host(h, &r);
	wbx_load_state(h, mem_read, (uintptr_t)&state, &r);
	CHECK(!r.error_message[0]);
	wbx_activate_host(h, &r);
	CHECK(GetAcc() == acc_at_save);
	CHECK(Step(0x33333333) == s3);   /* deterministic replay from the restored point */

	/* the guest's control words are in a state, and a state from before they
	 * were (no GuestFpuState1 record) loads with the values every guest
	 * starts from */
	{
		typedef uint64_t (MB_GUEST_ABI *u64_fn)(void);
		typedef void (MB_GUEST_ABI *fpuset_fn)(uint32_t, uint32_t);
		((fpuset_fn)proc(h, "FpuSet"))(FPU_GUEST_CW, FPU_GUEST_MX);
		membuf fs = {0};
		wbx_deactivate_host(h, &r);
		wbx_save_state(h, mem_write, (uintptr_t)&fs, &r);
		CHECK(!r.error_message[0]);
		CHECK(state_contains(&fs, "GuestFpuState1"));
		wbx_activate_host(h, &r);
		((fpuset_fn)proc(h, "FpuSet"))(FPU_START_CW, FPU_START_MX);
		fs.pos = 0;
		wbx_deactivate_host(h, &r);
		wbx_load_state(h, mem_read, (uintptr_t)&fs, &r);
		CHECK(!r.error_message[0]);
		wbx_activate_host(h, &r);
		uint64_t seen = ((u64_fn)proc(h, "FpuSeen"))();
		CHECK((seen >> 32) == FPU_GUEST_CW && ((uint32_t)seen & ~FPU_FLAGS) == FPU_GUEST_MX);
		/* the same state with the record cut out, as an older build wrote it */
		size_t at = 0;
		while (at + 14 <= fs.len && memcmp(fs.buf + at, "GuestFpuState1", 14) != 0) at++;
		CHECK(at + 20 <= fs.len);
		memmove(fs.buf + at, fs.buf + at + 20, fs.len - at - 20);
		fs.len -= 20;
		fs.pos = 0;
		wbx_deactivate_host(h, &r);
		wbx_load_state(h, mem_read, (uintptr_t)&fs, &r);
		CHECK(!r.error_message[0]);
		wbx_activate_host(h, &r);
		seen = ((u64_fn)proc(h, "FpuSeen"))();
		CHECK((seen >> 32) == FPU_START_CW && ((uint32_t)seen & ~FPU_FLAGS) == FPU_START_MX);
		free(fs.buf);
	}

	/* system calls handed freed memory answer EFAULT; the machine lives on */
	{
		typedef uint32_t (MB_GUEST_ABI *u32_fn)(void);
		const uint32_t bad = ((u32_fn)proc(h, "BadPointersRefused"))();
		printf("run_guest: system calls handed freed memory: %#x (expect 0)\n", (unsigned)bad);
		CHECK(bad == 0);
		char why[512];
		wbx_get_death(h, why, sizeof why, &r);
		CHECK(r.data == 0);
	}

	/* Open files and the getrandom stream are in states and deltas
	 * (2026-10-18). A descriptor closed after the save and opened again on
	 * another file - a disc swap gets the same number - reads the first file
	 * after the load, from where it was; the entropy stream goes on from where
	 * it was. A state from before (no OpenFileTable1 record) loads leaving
	 * both as they are. */
	{
		typedef int (MB_GUEST_ABI *disc_open_fn)(int);
		typedef int (MB_GUEST_ABI *int_fn)(void);
		typedef uint32_t (MB_GUEST_ABI *u32_fn)(void);
		typedef uint64_t (MB_GUEST_ABI *u64_fn)(void);
		disc_open_fn DiscOpen = (disc_open_fn)proc(h, "DiscOpen");
		int_fn DiscClose = (int_fn)proc(h, "DiscClose");
		u32_fn DiscRead4 = (u32_fn)proc(h, "DiscRead4");
		u64_fn Entropy = (u64_fn)proc(h, "Entropy");
		const int fd = DiscOpen(0);
		CHECK(fd >= 3);
		CHECK(DiscRead4() == 0x43424140u);           /* disc1, bytes 0..3 */
		membuf fst = {0};
		wbx_deactivate_host(h, &r);
		wbx_save_state(h, mem_write, (uintptr_t)&fst, &r);
		CHECK(!r.error_message[0]);
		CHECK(state_contains(&fst, "OpenFileTable1"));
		wbx_activate_host(h, &r);
		const uint32_t next = DiscRead4();           /* bytes 4..7 */
		const uint64_t e1 = Entropy();
		CHECK(DiscClose() == 0);
		CHECK(DiscOpen(1) == fd);                     /* the next disc, the same descriptor */
		CHECK(DiscRead4() == 0x83828180u);
		fst.pos = 0;
		wbx_deactivate_host(h, &r);
		wbx_load_state(h, mem_read, (uintptr_t)&fst, &r);
		CHECK(!r.error_message[0]);
		wbx_activate_host(h, &r);
		const uint32_t again = DiscRead4();
		printf("run_guest: after a load the descriptor reads %08x (it read %08x there before the swap)\n",
		       (unsigned)again, (unsigned)next);
		CHECK(next == 0x47464544u && again == next);
		CHECK(Entropy() == e1);
		/* a delta carries them too: from a state taken at the mark, the delta
		 * lands on the machine after a swap, descriptor and stream included */
		membuf mark = {0};
		wbx_deactivate_host(h, &r);
		wbx_save_state(h, mem_write, (uintptr_t)&mark, &r);
		CHECK(!r.error_message[0]);
		wbx_epoch_begin(h, &r);
		CHECK(!r.error_message[0]);
		wbx_activate_host(h, &r);
		CHECK(DiscRead4() == 0x4B4A4948u);           /* disc1, bytes 8..11 */
		(void)Entropy();
		CHECK(DiscClose() == 0);
		CHECK(DiscOpen(1) == fd);
		CHECK(DiscRead4() == 0x83828180u);           /* disc2, bytes 0..3 */
		membuf fwd = {0};
		wbx_deactivate_host(h, &r);
		wbx_save_delta(h, true, mem_write, (uintptr_t)&fwd, &r);
		if (r.error_message[0]) printf("run_guest: save_delta: %s\n", r.error_message);
		CHECK(!r.error_message[0]);
		wbx_activate_host(h, &r);
		const uint32_t then = DiscRead4();           /* disc2, bytes 4..7 */
		const uint64_t e3 = Entropy();
		mark.pos = 0;
		wbx_deactivate_host(h, &r);
		wbx_load_state(h, mem_read, (uintptr_t)&mark, &r);
		CHECK(!r.error_message[0]);
		wbx_load_delta(h, mem_read, (uintptr_t)&fwd, &r);
		if (r.error_message[0]) printf("run_guest: load_delta: %s\n", r.error_message);
		CHECK(!r.error_message[0]);
		wbx_activate_host(h, &r);
		CHECK(then == 0x87868584u && DiscRead4() == then);
		CHECK(Entropy() == e3);
		free(mark.buf);
		free(fwd.buf);
		/* the state with the record cut out, as an older build wrote it: it
		 * loads, and the descriptor goes on as it is now (disc2 at 8) */
		size_t at = 0;
		while (at + 14 <= fst.len && memcmp(fst.buf + at, "OpenFileTable1", 14) != 0) at++;
		size_t end = at;
		while (end + 8 <= fst.len && memcmp(fst.buf + end, "\xcb\x87soHxoq", 8) != 0) end++;
		CHECK(at < end && end + 8 <= fst.len);
		memmove(fst.buf + at, fst.buf + end, fst.len - end);
		fst.len -= end - at;
		fst.pos = 0;
		wbx_deactivate_host(h, &r);
		wbx_load_state(h, mem_read, (uintptr_t)&fst, &r);
		CHECK(!r.error_message[0]);
		wbx_activate_host(h, &r);
		CHECK(DiscRead4() == 0x8B8A8988u);           /* disc2, bytes 8..11 */
		/* A state naming a file that is not mounted here (a disc renamed since):
		 * it loads, leaving the open files as they are, as every state did
		 * before they were recorded - refusing would come after the memory
		 * was replaced. */
		membuf good = {0};
		wbx_deactivate_host(h, &r);
		wbx_save_state(h, mem_write, (uintptr_t)&good, &r);  /* disc2 at 12 */
		CHECK(!r.error_message[0]);
		wbx_activate_host(h, &r);
		CHECK(DiscRead4() == 0x8F8E8D8Cu);           /* disc2, bytes 12..15 */
		membuf ren = { malloc(good.len), good.len, good.len, 0 };
		memcpy(ren.buf, good.buf, good.len);
		size_t rec = 0;
		while (rec + 14 <= ren.len && memcmp(ren.buf + rec, "OpenFileTable1", 14) != 0) rec++;
		size_t nm = rec;
		while (nm + 5 <= ren.len && memcmp(ren.buf + nm, "disc2", 5) != 0) nm++;
		CHECK(rec < nm && nm + 5 <= ren.len);
		if (nm + 5 <= ren.len) ren.buf[nm + 4] = 'X';   /* "discX" */
		wbx_deactivate_host(h, &r);
		wbx_load_state(h, mem_read, (uintptr_t)&ren, &r);
		CHECK(!r.error_message[0]);
		wbx_activate_host(h, &r);
		CHECK(DiscRead4() == 0x93929190u);           /* disc2, bytes 16..19: left as it was */
		/* A state that stops loading half way, cut short inside its thread set,
		 * after its memory went in: the machine is dead until a state loads.
		 * One refused before any memory moved (another machine's hash) is not. */
		size_t ts = 0;
		while (ts + 14 <= good.len && memcmp(good.buf + ts, "GuestThreadSet", 14) != 0) ts++;
		CHECK(ts + 20 <= good.len);
		memreader cut = { good.buf, ts + 20, 0 };
		char why[512];
		wbx_deactivate_host(h, &r);
		wbx_load_state(h, mem_reader, (uintptr_t)&cut, &r);
		CHECK(r.error_message[0] != 0);
		wbx_get_death(h, why, sizeof why, &r);
		printf("run_guest: a state cut short in its thread set: dead=%llu: %s\n", (unsigned long long)r.data, why);
		CHECK(r.data == 1 && strstr(why, "half way") != NULL);
		good.pos = 0;
		wbx_load_state(h, mem_read, (uintptr_t)&good, &r);
		CHECK(!r.error_message[0]);
		wbx_get_death(h, why, sizeof why, &r);
		CHECK(r.data == 0);
		ren.buf[60] ^= 0xFF;                          /* inside the ELF hash: refused up front */
		ren.pos = 0;
		wbx_load_state(h, mem_read, (uintptr_t)&ren, &r);
		CHECK(r.error_message[0] != 0);
		wbx_get_death(h, why, sizeof why, &r);
		CHECK(r.data == 0);
		wbx_activate_host(h, &r);
		CHECK(DiscRead4() == 0x8F8E8D8Cu);           /* the good state's machine: disc2 at 12 */
		free(good.buf);
		free(ren.buf);
		CHECK(DiscClose() == 0);
		free(fst.buf);
	}

	wbx_deactivate_host(h, &r);
#ifndef _WIN32
	{
		pthread_t t;
		void *size = NULL;
		CHECK(pthread_create(&t, NULL, small_altstack_thread, h) == 0);
		pthread_join(t, &size);
		printf("run_guest: a thread with a 16 KiB signal stack has %zu KiB after activating\n", (size_t)(uintptr_t)size / 1024);
		CHECK((uintptr_t)size >= 256 * 1024);
	}
#endif
	wbx_destroy_host(h, &r);

	/* ---- determinism across two independent hosts, same seed ---- */
	mb_host *h2 = make_host(path, 0xABCD);
	wbx_activate_host(h2, &r);
	((setcb_fn)proc(h2, "SetLogCallback"))(0);   /* no callback this time */
	CHECK(((init_fn)proc(h2, "Init"))() == 1);
	wbx_deactivate_host(h2, &r); wbx_seal(h2, &r); wbx_activate_host(h2, &r);
	uint32_t a = ((step_fn)proc(h2, "Step"))(0x11111111);
	uint32_t bb = ((step_fn)proc(h2, "Step"))(0x22222222);
	CHECK(a == s1 && bb == s2);   /* same seed + inputs -> identical results */
	wbx_deactivate_host(h2, &r); wbx_destroy_host(h2, &r);

	/* ---- different seed -> different result ---- */
	mb_host *h3 = make_host(path, 0x9999);
	wbx_activate_host(h3, &r);
	((setcb_fn)proc(h3, "SetLogCallback"))(0);
	((init_fn)proc(h3, "Init"))();
	wbx_deactivate_host(h3, &r); wbx_seal(h3, &r); wbx_activate_host(h3, &r);
	CHECK(((step_fn)proc(h3, "Step"))(0x11111111) != s1);
	wbx_deactivate_host(h3, &r); wbx_destroy_host(h3, &r);

	/* ---- error paths ---- */
	/* save before seal -> error */
	mb_host *he = make_host(path, 1);
	wbx_activate_host(he, &r);
	((init_fn)proc(he, "Init"))();
	wbx_deactivate_host(he, &r);
	membuf junk = {0};
	wbx_save_state(he, mem_write, (uintptr_t)&junk, &r);
	CHECK(r.error_message[0] != 0);
	/* double seal -> error */
	wbx_seal(he, &r); CHECK(!r.error_message[0]);
	wbx_seal(he, &r); CHECK(r.error_message[0] != 0);
	/* missing proc -> 0, not an error */
	wbx_activate_host(he, &r);
	wbx_get_proc_addr(he, "NoSuchExport", &r);
	CHECK(!r.error_message[0] && r.data == 0);
	/* out-of-range callback slot -> error */
	wbx_get_callback_addr(he, log_cb, 999, &r);
	CHECK(r.error_message[0] != 0);
	wbx_deactivate_host(he, &r);
	wbx_destroy_host(he, &r);

	/* ---- corrupt-state rejection: flip the embedded ELF hash ---- */
	CHECK(state.len > 100);
	state.buf[60] ^= 0xFF;   /* somewhere inside the ElfLoader hash region */
	mb_host *hc = make_host(path, 0xABCD);
	wbx_activate_host(hc, &r); ((init_fn)proc(hc, "Init"))();
	wbx_deactivate_host(hc, &r); wbx_seal(hc, &r);
	memreader corrupt = { state.buf, state.len, 0 };
	wbx_load_state(hc, mem_reader, (uintptr_t)&corrupt, &r);
	CHECK(r.error_message[0] != 0);   /* corrupted state rejected */
	wbx_destroy_host(hc, &r);

	free(state.buf); free(junk.buf);

	/* ---- a guest that dies does not take the host with it ---- */
	guest_deaths_are_survived(path);
#ifdef _WIN32
	out_of_memory_is_said(path);
#endif

	/* ---- a destroyed machine is not what the fault handler reads (chimera#127) ----
	 * The handler names the region an address landed in by reading the live
	 * machine's layout, and that layout lives INSIDE the mb_host. A host that is
	 * freed without taking it back leaves the handler reading a dead heap chunk
	 * on the next fault anywhere in the process - and on Windows that chunk is
	 * really gone, so the handler faults, is called again for its own fault, and
	 * the process dies of a stack overflow. Both halves are checked, because a
	 * NULL that was never set would pass the second on its own. */
	STAGE("checking that a destroyed host gives its layout back");
	{
		mb_host *hl = make_host(path, 0xABCD);
		wbx_activate_host(hl, &r);
		CHECK(mb_tripguard_layout() != NULL);   /* a live machine has one */
		wbx_deactivate_host(hl, &r);
		wbx_destroy_host(hl, &r);
		CHECK(mb_tripguard_layout() == NULL);   /* a dead one does not */
	}

#ifndef _WIN32
	/* ---- a fault in host code is passed on, and said to be ---- */
	STAGE("checking that a host fault is reported as passed on, not unhandled");
	CHECK(host_fault_is_reported_as_passed_on(argv[0], path));
#else
	/* ---- the handler does not fault on its own diagnosis for ever ----
	 * Windows only, because only Windows re-enters a vectored handler for its
	 * own fault; a POSIX SIGSEGV inside the SIGSEGV handler, with the signal
	 * blocked, kills the process at once and cannot recurse. */
	STAGE("checking that a handler which faults while reporting stops instead of recursing");
	CHECK(handler_does_not_recurse(argv[0], path));
#endif

	/* ---- a guest that aborts says why, in the diagnostic log ---- */
	STAGE("checking that a guest abort is reported with its last words");
	CHECK(guest_abort_is_reported(argv[0], path));

	if (fails == 0) printf("run_guest: all checks passed\n");
	else printf("run_guest: %d checks FAILED\n", fails);
	return fails ? 1 : 0;
}
