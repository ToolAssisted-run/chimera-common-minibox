/* miniBox conformance guest for spec v3 (virtual time). Same toolchain as the
 * v2 guest, but declares __wbx_machine_spec = 3 and exercises the clock,
 * timed waits, save/load across a wait, mremap moves, hints and O_TRUNC.
 * Every export returns 1 on pass, 0 on fail; the runner CHECKs each, and
 * orchestrates the save/load dance around SetupWaiter/ExpireStep. Raw
 * syscall() throughout: libc wrappers would add their own retries and hide
 * exact returns. */
#define _GNU_SOURCE
#include <emulibc.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/mman.h>

__attribute__((visibility("default"))) __attribute__((used))
const uint32_t __wbx_machine_spec = 3;

ECL_EXPORT int Init(void) { return 1; }

#define BASE_SEC 1495889068ll
#define TICK_NS 1000ull
#define ETIMEDOUT_LINUX 110

static long raw_clock(struct timespec *ts) { return syscall(SYS_clock_gettime, 0, ts); }
static uint64_t vnow(void) { struct timespec ts; raw_clock(&ts); return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec; }

/* successive reads tick exactly 1 us (no absolute base asserted: Init may
 * have ticked before the first export runs) */
ECL_EXPORT int V3ClockTicks(void) {
	uint64_t a = vnow(), b = vnow(), c = vnow();
	struct timespec ts; raw_clock(&ts);
	if (ts.tv_sec != BASE_SEC) return 0;
	if (b - a != TICK_NS || c - b != TICK_NS) return 0;
	return 1;
}

/* nanosleep advances by exactly the request (+ the check reads' ticks);
 * clock_nanosleep relative, absolute future and absolute past */
ECL_EXPORT int V3NanosleepExact(void) {
	struct timespec req, rem;
	uint64_t a = vnow();
	req.tv_sec = 0; req.tv_nsec = 2500;
	if (syscall(SYS_nanosleep, &req, NULL) != 0) return 0;
	uint64_t b = vnow();
	if (b - a != 2500 + TICK_NS) return 0;
	uint64_t c = vnow();
	req.tv_sec = 0; req.tv_nsec = 1500;
	if (syscall(SYS_clock_nanosleep, 0, 0, &req, &rem) != 0) return 0;
	if (rem.tv_sec != 0 || rem.tv_nsec != 0) return 0;
	uint64_t d = vnow();
	if (d - c != 1500 + TICK_NS) return 0;
	uint64_t e = vnow();
	uint64_t target = e + 2000;
	req.tv_sec = target / 1000000000ull; req.tv_nsec = target % 1000000000ull;
	if (syscall(SYS_clock_nanosleep, 0, 1 /*TIMER_ABSTIME*/, &req, NULL) != 0) return 0;
	uint64_t f = vnow();
	if (f - e != 2000 + TICK_NS) return 0;
	uint64_t past = f - 5000;
	req.tv_sec = past / 1000000000ull; req.tv_nsec = past % 1000000000ull;
	if (syscall(SYS_clock_nanosleep, 0, 1, &req, NULL) != 0) return 0;
	uint64_t g = vnow();
	if (g - f != TICK_NS) return 0;
	return 1;
}

/* WAIT_BITSET absolute: a past deadline expires at once (one tick, no jump);
 * a future one fast-forwards the clock to itself */
ECL_EXPORT int V3WaitBitset(void) {
	static int atom = 0;
	struct timespec to;
	uint64_t a = vnow();
	uint64_t p = a - 5000;
	to.tv_sec = p / 1000000000ull; to.tv_nsec = p % 1000000000ull;
	errno = 0;
	if (syscall(SYS_futex, &atom, 9 | 128 /*WAIT_BITSET|PRIVATE*/, 0, &to, NULL, 0xFFFFFFFF) != -1
	    || errno != ETIMEDOUT_LINUX) return 0;
	uint64_t b = vnow();
	if (b - a != 2 * TICK_NS) return 0;
	uint64_t t = b + 5000;
	to.tv_sec = t / 1000000000ull; to.tv_nsec = t % 1000000000ull;
	errno = 0;
	if (syscall(SYS_futex, &atom, 9 | 128, 0, &to, NULL, 0xFFFFFFFF) != -1
	    || errno != ETIMEDOUT_LINUX) return 0;
	uint64_t c = vnow();
	if (c - b != 5000 + TICK_NS) return 0;
	return 1;
}

/* one waiter, no waker: fast-forward wakes it at its deadline, the clock
 * stands exactly there (+ this read's tick), and the answer is ETIMEDOUT */
ECL_EXPORT int V3TimedWaitExpires(void) {
	static int atom = 0;
	struct timespec to = { 0, 5000 };
	uint64_t a = vnow();
	errno = 0;
	long r = syscall(SYS_futex, &atom, 0 /*WAIT*/, 0, &to, NULL, 0);
	int e = errno;
	uint64_t b = vnow();
	if (r != -1 || e != ETIMEDOUT_LINUX) return 0;
	if (b - a != 5000 + TICK_NS) return 0;
	return 1;
}

/* ---- deadline order across threads ----
 * B (short deadline) must expire while A (long deadline) stays parked through
 * the same advance; A woken explicitly must answer 0, not ETIMEDOUT. Then a
 * same-deadline pair must both expire. Join is the rendezvous: a joined
 * waiter ran to completion, so no interleaving can leak into the asserts. */
static int fut_a, fut_b, fut_c, fut_d;
static volatile int ready_a, ready_b;
static long ret_a, ret_b, ret_c, ret_d;
static int err_b, err_c, err_d, err_w;
static uint64_t obs_b, dl_b;

/* each waiter records its own park-time deadline: immune to whatever the
 * spawner's libc ticked between the spawner's clock read and the park */
static void *waiter_short(void *arg) {
	(void)arg;
	struct timespec to = { 0, 20000 };
	dl_b = vnow() + 20000;
	ready_b = 1;
	errno = 0;
	ret_b = syscall(SYS_futex, &fut_b, 0 /*WAIT*/, 0, &to, NULL, 0);
	err_b = errno;
	obs_b = vnow();
	return 0;
}
static void *waiter_long(void *arg) {
	(void)arg;
	struct timespec to = { 0, 100000 };
	ready_a = 1;
	ret_a = syscall(SYS_futex, &fut_a, 0 /*WAIT*/, 0, &to, NULL, 0);
	return 0;
}
static void *waiter_tie(void *arg) {
	int *fut = arg;
	struct timespec to = { 0, 30000 };
	errno = 0;
	long r = syscall(SYS_futex, fut, 0 /*WAIT*/, 0, &to, NULL, 0);
	if (fut == &fut_c) { ret_c = r; err_c = errno; } else { ret_d = r; err_d = errno; }
	return 0;
}

ECL_EXPORT int V3WaitOrder(void) {
	pthread_t ta, tb, tc, td;
	if (pthread_create(&tb, 0, waiter_short, 0) != 0) return 0;
	pthread_join(tb, 0);
	if (ret_b != -1 || err_b != ETIMEDOUT_LINUX) return 0;
	if (obs_b != dl_b + TICK_NS) return 0;
	if (pthread_create(&ta, 0, waiter_long, 0) != 0) return 0;
	while (!ready_a) syscall(SYS_sched_yield);   /* yields don't tick */
	struct timespec sl = { 0, 50000 };
	syscall(SYS_nanosleep, &sl, NULL);           /* past B's scale, short of A's */
	long w = syscall(SYS_futex, &fut_a, 1 /*WAKE*/, 1, NULL, NULL, 0);
	if (w != 1) return 0;                        /* A was still parked */
	pthread_join(ta, 0);
	if (ret_a != 0) return 0;                    /* woken, not expired */
	if (pthread_create(&tc, 0, waiter_tie, &fut_c) != 0) return 0;
	if (pthread_create(&td, 0, waiter_tie, &fut_d) != 0) return 0;
	struct timespec sl2 = { 0, 100000 };
	syscall(SYS_nanosleep, &sl2, NULL);
	pthread_join(tc, 0); pthread_join(td, 0);
	if (ret_c != -1 || err_c != ETIMEDOUT_LINUX || ret_d != -1 || err_d != ETIMEDOUT_LINUX) return 0;
	return 1;
}

/* ---- save/load in the middle of a timed wait (runner-orchestrated) ----
 * SetupWaiter parks W (deadline recorded for the runner); ExpireStep advances
 * past it, joins, and reports the clock W saw. The runner saves between the
 * two calls, loads, and repeats: both runs must expire at the same time. The
 * one yield is a deterministic rendezvous (two threads, ascending tids): W
 * runs exactly once and parks; ready==0 would fail loudly, not silently. */
static int fut_w;
static volatile int ready_w;
static pthread_t tw;
static long ret_w;
static uint64_t obs_w, deadline_w;

static void *waiter_saved(void *arg) {
	(void)arg;
	struct timespec to = { 0, 50000 };
	deadline_w = vnow() + 50000;
	ready_w = 1;
	errno = 0;
	ret_w = syscall(SYS_futex, &fut_w, 0 /*WAIT*/, 0, &to, NULL, 0);
	err_w = errno;
	obs_w = vnow();
	return 0;
}
ECL_EXPORT int SetupWaiter(void) {
	ready_w = 0;
	pthread_t tw2;
	if (pthread_create(&tw2, 0, waiter_saved, 0) != 0) return 0;
	tw = tw2;
	/* a loop, not one yield: W's own clock read yields back here before it
	 * parks, so one handoff is never enough. Yields don't tick, so the count
	 * is unobservable. */
	for (int i = 0; i < 100 && !ready_w; i++) syscall(SYS_sched_yield);
	if (!ready_w) return 0;
	return 1;
}
ECL_EXPORT uint64_t GetDeadline(void) { return deadline_w; }
ECL_EXPORT uint64_t ExpireStep(void) {
	/* advance to exactly the deadline (not past it): the wake then lands
	 * on deadline+tick, identically with and without a save/load between */
	uint64_t c = vnow();
	uint64_t ns = (deadline_w > c) ? deadline_w - c : 0;
	struct timespec sl = { (long)(ns / 1000000000ull), (long)(ns % 1000000000ull) };
	syscall(SYS_nanosleep, &sl, NULL);
	pthread_join(tw, 0);
	if (ret_w != -1 || err_w != ETIMEDOUT_LINUX) return 0;
	return obs_w;
}

/* ---- mremap moves, hints, O_TRUNC ---- */
ECL_EXPORT int V3MremapMoves(void) {
	uint8_t *p1 = (uint8_t *)syscall(SYS_mmap, 0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p1 == MAP_FAILED) return 0;
	for (int i = 0; i < 8192; i++) p1[i] = (uint8_t)(i & 0xFF);
	/* block the in-place grow however the arena lies: a NOREPLACE probe at
	 * p1+8192 either maps it (occupied now) or finds it taken (EEXIST) */
	uint8_t *fill = (uint8_t *)syscall(SYS_mmap, p1 + 8192, 8192, PROT_READ | PROT_WRITE,
	                                   MAP_PRIVATE | MAP_ANONYMOUS | 0x100000 /*NOREPLACE*/, -1, 0);
	if (fill == MAP_FAILED && errno != EEXIST) return 0;
	(void)fill;
	long r = syscall(SYS_mremap, p1, 8192, 16384, 0);
	if (r != -1 || errno != 17 /*EEXIST*/) return 0;
	uint8_t *p2 = (uint8_t *)syscall(SYS_mremap, p1, 8192, 16384, 1 /*MAYMOVE*/);
	if (p2 == MAP_FAILED || p2 == p1) return 0;
	for (int i = 0; i < 8192; i++) if (p2[i] != (uint8_t)(i & 0xFF)) return 0;
	r = syscall(SYS_mremap, p2, 16384, 8192, 0);
	if ((uint8_t *)r != p2) return 0;        /* shrink never moves */
	r = syscall(SYS_mremap, p2, 8192, 16384, 1 | 2 /*MAYMOVE|FIXED*/);
	if (r != -1 || errno != 22 /*EINVAL*/) return 0;
	return 1;
}

ECL_EXPORT int V3HintHonored(void) {
	uint8_t *h1 = (uint8_t *)syscall(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (h1 == MAP_FAILED) return 0;
	uint8_t *h2 = (uint8_t *)syscall(SYS_mmap, h1, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (h2 == MAP_FAILED || h2 == h1) return 0;   /* occupied: placed elsewhere */
	h2[0] = 0xAB;                                  /* ...and valid */
	uint8_t *h3 = (uint8_t *)syscall(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (h3 == MAP_FAILED) return 0;
	if (syscall(SYS_munmap, h3, 4096) != 0) return 0;
	uint8_t *h4 = (uint8_t *)syscall(SYS_mmap, h3, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (h4 != h3) return 0;                        /* freed: honoured */
	/* MAP_FIXED is not a hint: it maps at the address, discarding overlap */
	uint8_t *f1 = (uint8_t *)syscall(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (f1 == MAP_FAILED) return 0;
	f1[0] = 0x11;
	uint8_t *f2 = (uint8_t *)syscall(SYS_mmap, f1, 4096, PROT_READ | PROT_WRITE,
	                                 MAP_PRIVATE | MAP_ANONYMOUS | 0x10 /*FIXED*/, -1, 0);
	if (f2 != f1) return 0;
	if (f2[0] != 0) return 0;                      /* discarded: zero-filled */
	/* decommit/recommit (PROT_NONE then RW, both MAP_FIXED) zero-fills too */
	f2[0] = 0x22;
	if (f1[0] != 0x22) return 0;
	if ((uint8_t *)syscall(SYS_mmap, f1, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | 0x10, -1, 0) != f1) return 0;
	if ((uint8_t *)syscall(SYS_mmap, f1, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | 0x10, -1, 0) != f1) return 0;
	if (f1[0] != 0) return 0;
	(void)h1;
	return 1;
}

ECL_EXPORT int V3OTrunc(void) {
	int fd = open("scratch", O_RDWR);
	if (fd < 0) return 0;
	if (write(fd, "hello", 5) != 5) return 0;
	close(fd);
	fd = open("scratch", O_RDWR | O_TRUNC);
	if (fd < 0) return 0;
	char buf[8];
	if (read(fd, buf, sizeof buf) != 0) return 0;  /* truncated */
	close(fd);
	if (open("scratch", O_RDONLY | O_TRUNC) >= 0) return 0;  /* needs write access */
	if (errno != EACCES) return 0;
	int so = open("/dev/stdout", O_WRONLY | O_TRUNC);
	if (so < 0) return 0;                          /* streams: ignored, not an error */
	close(so);
	return 1;
}
