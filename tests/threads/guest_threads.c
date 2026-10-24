/* A guest that exercises the green-thread path: it spawns N pthreads that each
 * increment a shared counter under a mutex a fixed number of times, joins them,
 * and reports the total. Correct cooperative scheduling + futex-backed
 * pthread_mutex + join must yield exactly N*ITERS. */
#define _POSIX_C_SOURCE 200809L  /* clock_gettime under -std=c11 */
#include <emulibc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sched.h>
#include <sys/mman.h>
#include <time.h>

#define NTHREADS 4
#define ITERS 1000

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile uint64_t g_counter;

static void *worker(void *arg) {
	(void)arg;
	for (int i = 0; i < ITERS; i++) {
		pthread_mutex_lock(&g_lock);
		g_counter++;
		pthread_mutex_unlock(&g_lock);
	}
	return 0;
}

ECL_EXPORT uint64_t RunThreads(void) {
	pthread_t th[NTHREADS];
	g_counter = 0;
	for (int i = 0; i < NTHREADS; i++)
		if (pthread_create(&th[i], 0, worker, 0) != 0) { fprintf(stderr, "pthread_create failed\n"); return 0; }
	for (int i = 0; i < NTHREADS; i++)
		pthread_join(th[i], 0);
	return g_counter;   /* must equal NTHREADS*ITERS */
}

/* a producer/consumer round using a condition variable, exercising futex
 * wait/wake and requeue via pthread_cond */
static pthread_mutex_t g_cvlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static volatile int g_ready;
static volatile uint64_t g_produced;

static void *consumer(void *arg) {
	(void)arg;
	pthread_mutex_lock(&g_cvlock);
	while (!g_ready) pthread_cond_wait(&g_cv, &g_cvlock);
	uint64_t v = g_produced;
	pthread_mutex_unlock(&g_cvlock);
	return (void *)(uintptr_t)v;
}

ECL_EXPORT uint64_t RunCondvar(uint64_t value) {
	pthread_t c;
	g_ready = 0; g_produced = 0;
	pthread_create(&c, 0, consumer, 0);
	pthread_mutex_lock(&g_cvlock);
	g_produced = value * 2 + 1;
	g_ready = 1;
	pthread_cond_signal(&g_cv);
	pthread_mutex_unlock(&g_cvlock);
	void *r = 0;
	pthread_join(c, &r);
	return (uint64_t)(uintptr_t)r;   /* must equal value*2+1 */
}

ECL_EXPORT int Init(void) { return 1; }
int main(void) { return 0; }

/* Thread-local storage, on a new thread and on the main one: a zeroed local
 * reads zero, an initialised one reads its initialiser, and neither shares
 * memory with the thread's stack. Until musl was handed the program's PT_TLS
 * they sat below the TLS block it reserved - on the top of a new thread's
 * stack, on static data for the main thread. */
static _Thread_local uint32_t t_zero[64];
static _Thread_local uint32_t t_init = 0x5eed1234u;

static __attribute__((noinline)) uint32_t tls_use_stack(int depth) {
	volatile uint8_t pad[512];
	for (int i = 0; i < 512; i++) pad[i] = (uint8_t)(0xa5 ^ depth);
	return depth ? tls_use_stack(depth - 1) + pad[7] : pad[3];
}

static uint64_t tls_check(int fresh) {
	uint64_t bad = 0;
	for (int i = 0; fresh && i < 64; i++) if (t_zero[i] != 0) bad |= 1;
	if (t_init != 0x5eed1234u) bad |= 2;
	for (int i = 0; i < 64; i++) t_zero[i] = 0x11111111u * (uint32_t)(i & 15);
	tls_use_stack(8);
	for (int i = 0; i < 64; i++) if (t_zero[i] != 0x11111111u * (uint32_t)(i & 15)) bad |= 4;
	return bad;
}

static void *tls_worker(void *arg) {
	(void)arg;
	return (void *)(uintptr_t)tls_check(1);
}

/* 0 when right; bits 0..2 the main thread's faults, 8..10 a new thread's */
ECL_EXPORT uint64_t RunTls(void) {
	static int main_seen;
	const uint64_t on_main = tls_check(!main_seen);
	main_seen = 1;
	pthread_t t;
	void *on_new = 0;
	if (pthread_create(&t, 0, tls_worker, 0) != 0) return 0xffff;
	pthread_join(t, &on_new);
	return on_main | (uint64_t)(uintptr_t)on_new << 8;
}

/* The guest's own fault handler (GuestFaultHandler), which an emulator's
 * write tracking uses: called on the faulting thread, it must run as guest
 * code does - its thread locals its own, its system calls accepted. Until it
 * ran under the guest's %fs it read the host's thread locals and its
 * mprotect arrived with a base the dispatcher refuses. */
static _Thread_local volatile uint32_t t_faults;   /* changed by the handler, under the compiler's feet */
static volatile uintptr_t g_watched, g_fatal, g_spin_page;
static volatile uint64_t g_handler_spins;
/* A page of its own that nothing but the handler writes, so that after sealing
 * it is a tracked clean page: the handler's write to it faults INSIDE the
 * handler, and that fault has to be served as any other. */
static volatile uint32_t g_handler_page[1024] __attribute__((aligned(4096)));

/* For RunFaultYield and RunFaultRegisters, below */
static volatile uintptr_t g_yield_page, g_other_page, g_clobber_page;
static volatile int g_other_done;
static int fault_yield(void);
static void clobber_registers(void);
static int have_avx(void);

ECL_EXPORT int GuestFaultHandler(uint64_t addr, uint64_t is_write) {
	(void)is_write;
	if (g_yield_page && addr >= g_yield_page && addr < g_yield_page + 4096)
		return fault_yield();
	if (g_other_page && addr >= g_other_page && addr < g_other_page + 4096) {
		t_faults++;
		return mprotect((void *)g_other_page, 4096, PROT_READ | PROT_WRITE) == 0;
	}
	if (g_clobber_page && addr >= g_clobber_page && addr < g_clobber_page + 4096) {
		clobber_registers();
		return mprotect((void *)g_clobber_page, 4096, PROT_READ | PROT_WRITE) == 0;
	}
	if (g_fatal && addr >= g_fatal && addr < g_fatal + 4096) {
		*(volatile uint32_t *)(uintptr_t)8 = 1;   /* dies in here: a fault no one handles */
		return 0;
	}
	if (g_spin_page && addr >= g_spin_page && addr < g_spin_page + 4096)
		for (;;) g_handler_spins++;   /* never comes back: SpinInFaultHandler */
	if (!g_watched || addr < g_watched || addr >= g_watched + 4096) return 0;
	t_faults++;
	g_handler_page[0]++;
	return mprotect((void *)g_watched, 4096, PROT_READ | PROT_WRITE) == 0;
}

/* 0 when right: the write lands, and the handler counted it in THIS thread's
 * thread local, and on its own held page */
/* The same handler, for a fault taken in HOST code: a system call the host
 * answers by writing into guest memory (clock_gettime's result), into a page
 * the guest protected. The thread is outside the guest while the host runs,
 * and the handler's own system call (mprotect) arrived with no context and
 * ended the process (chimera issue 280). 0 when right: the call returns, the
 * result is in the page, and the handler counted the fault once. */
ECL_EXPORT uint64_t RunHostWriteFault(void) {
	volatile uint8_t *page = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED) return 0xff;
	page[0] = 1;
	if (mprotect((void *)page, 4096, PROT_READ) != 0) return 0xfe;
	const uint32_t before = t_faults;
	g_watched = (uintptr_t)page;
	struct timespec *ts = (struct timespec *)(uintptr_t)page;
	const int r = clock_gettime(CLOCK_MONOTONIC, ts);   /* the host writes the page */
	g_watched = 0;
	uint64_t bad = 0;
	if (r != 0) bad |= 1;
	if (ts->tv_sec == 0 && ts->tv_nsec == 0) bad |= 2;
	if (t_faults != before + 1) bad |= 4;
	munmap((void *)page, 4096);
	return bad;
}

/* For a frontend's memory tools, which read between frames from a thread
 * that is not the guest's: a page the guest made no-access, filled with a
 * pattern and watched by the handler. The host reads it through
 * wbx_guest_read_view (the handler must not run) and then, as the control,
 * through the guest's own view (it must). 0 when it could not be set up. */
static volatile uint8_t *g_read_page;
ECL_EXPORT uint64_t WatchForHostRead(void) {
	g_read_page = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (g_read_page == MAP_FAILED) return 0;
	for (int i = 0; i < 4096; i++) g_read_page[i] = (uint8_t)(i * 7 + 3);
	if (mprotect((void *)g_read_page, 4096, PROT_NONE) != 0) return 0;
	g_watched = (uintptr_t)g_read_page;
	return (uint64_t)(uintptr_t)g_read_page;
}
/* how many times the handler has run on a watched page */
ECL_EXPORT uint64_t HandlerRuns(void) { return g_handler_page[0]; }
ECL_EXPORT uint64_t EndHostRead(void) {
	g_watched = 0;
	return munmap((void *)g_read_page, 4096) == 0;
}

ECL_EXPORT uint64_t RunGuestFault(void) {
	/* volatile: the write must happen while the page is watched, not be
	 * moved past the store that stops watching it */
	volatile uint8_t *page = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED) return 0xff;
	page[0] = 1;
	if (mprotect((void *)page, 4096, PROT_READ) != 0) return 0xfe;
	const uint32_t before = t_faults, before_page = g_handler_page[0];
	g_watched = (uintptr_t)page;
	page[1] = 0x5a;   /* faults; the handler opens the page and it is retried */
	g_watched = 0;
	uint64_t bad = 0;
	if (page[1] != 0x5a) bad |= 1;
	if (t_faults != before + 1) bad |= 2;
	if (g_handler_page[0] != before_page + 1) bad |= 4;
	munmap((void *)page, 4096);
	return bad;
}

/* Never returns: the handler dies inside itself (a fault nested in the
 * guest's handler that nothing handles), which is the machine's death. */
ECL_EXPORT uint64_t RunGuestFaultDeath(void) {
	volatile uint8_t *page = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED) return 0xff;
	if (mprotect((void *)page, 4096, PROT_READ) != 0) return 0xfe;
	g_fatal = (uintptr_t)page;
	page[1] = 0x5a;
	return 0xfd;
}

/* A fault handler that gives way to another thread, which faults in turn and
 * runs the handler too, before the first one finishes - as RPCS3's renderer
 * does when its handler waits for a flush. On Linux the handler used to run
 * on the host's alternate signal stack, and the second thread's fault built
 * its signal frame over the first handler's, which was still paused there
 * (2026-10-18). Each thread now runs the handler on its own stack. */
static void *other_faulter(void *arg) {
	(void)arg;
	((volatile uint8_t *)g_other_page)[2] = 0x77;   /* faults; the handler opens the page */
	g_other_done = 1;
	return 0;
}

static int fault_yield(void) {
	pthread_t t;
	if (pthread_create(&t, 0, other_faulter, 0) != 0) return 0;
	while (!g_other_done) sched_yield();
	pthread_join(t, 0);
	t_faults++;
	return mprotect((void *)g_yield_page, 4096, PROT_READ | PROT_WRITE) == 0;
}

/* 0 when right: both writes land, each handled once, on its own thread */
ECL_EXPORT uint64_t RunFaultYield(void) {
	volatile uint8_t *a = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	volatile uint8_t *b = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (a == MAP_FAILED || b == MAP_FAILED) return 0xff;
	a[0] = 1; b[0] = 1;
	if (mprotect((void *)a, 4096, PROT_READ) != 0 || mprotect((void *)b, 4096, PROT_READ) != 0) return 0xfe;
	const uint32_t before = t_faults;
	g_other_done = 0;
	g_other_page = (uintptr_t)b;
	g_yield_page = (uintptr_t)a;
	a[1] = 0x5a;   /* faults; the handler waits for the other thread's fault */
	g_yield_page = 0;
	g_other_page = 0;
	uint64_t bad = 0;
	if (a[1] != 0x5a) bad |= 1;
	if (b[2] != 0x77) bad |= 2;
	if (!g_other_done) bad |= 4;
	if (t_faults != before + 1) bad |= 8;   /* thread locals: the other thread counted in its own */
	munmap((void *)a, 4096);
	munmap((void *)b, 4096);
	return bad;
}

/* What a function may change, changed, so that the code a fault interrupted
 * must get its registers back from whatever ran the handler. */
static void clobber_registers(void) {
	__asm__ volatile(
		"movq $-1, %%rax\n\t"
		"movq $-1, %%rcx\n\t"
		"movq $-1, %%rdx\n\t"
		"movq $-1, %%rsi\n\t"
		"movq $-1, %%rdi\n\t"
		"movq $-1, %%r8\n\t"
		"movq $-1, %%r9\n\t"
		"movq $-1, %%r10\n\t"
		"movq $-1, %%r11\n\t"
		"pcmpeqd %%xmm0, %%xmm0\n\t"
		"pcmpeqd %%xmm8, %%xmm8\n\t"
		"pcmpeqd %%xmm15, %%xmm15\n\t"
		"clc\n\t"
		::: "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
		    "xmm0", "xmm8", "xmm15", "cc", "memory");
	if (have_avx()) __asm__ volatile("vzeroall" ::: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
		"xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
}

static int have_avx(void) {
	uint32_t a, b, c, d;
	__asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
	if (!(c & (1u << 27)) || !(c & (1u << 28))) return 0;   /* OSXSAVE and AVX */
	uint32_t lo, hi;
	__asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
	return (lo & 6) == 6;
}

/* 0 when right: every register the faulting code held, and the carry flag,
 * are what they were before the fault, although the handler changed them */
ECL_EXPORT uint64_t RunFaultRegisters(void) {
	volatile uint8_t *page = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED) return 0xff;
	page[0] = 1;
	if (mprotect((void *)page, 4096, PROT_READ) != 0) return 0xfe;
	const int avx = have_avx();
	uint64_t out[20] = { (uint64_t)(uintptr_t)page };
	uint64_t *outp = out;
	g_clobber_page = (uintptr_t)page;
	__asm__ volatile(
		"movq %[outp], %%r15\n\t"
		"movq (%%r15), %%r14\n\t"   /* the page */
		"movabsq $0x1111111111111111, %%rax\n\t"
		"movabsq $0x2222222222222222, %%rbx\n\t"
		"movabsq $0x3333333333333333, %%rcx\n\t"
		"movabsq $0x4444444444444444, %%rdx\n\t"
		"movabsq $0x5555555555555555, %%rsi\n\t"
		"movabsq $0x6666666666666666, %%rdi\n\t"
		"movabsq $0x7777777777777777, %%r8\n\t"
		"movabsq $0x8888888888888888, %%r9\n\t"
		"movabsq $0x9999999999999999, %%r10\n\t"
		"movabsq $0xaaaaaaaaaaaaaaaa, %%r11\n\t"
		"movabsq $0xbbbbbbbbbbbbbbbb, %%r12\n\t"
		"movabsq $0xcccccccccccccccc, %%r13\n\t"
		"movq %%rax, %%xmm0\n\t"
		"movq %%rbx, %%xmm8\n\t"
		"movq %%rcx, %%xmm15\n\t"
		"cmpl $0, %[avx]\n\t"
		"je 1f\n\t"
		"vinsertf128 $1, %%xmm8, %%ymm8, %%ymm8\n"   /* the upper half too */
		"1:\n\t"
		"stc\n\t"
		"movb $0x5a, 1(%%r14)\n\t"   /* faults; the handler changes everything it may */
		"setc 8(%%r15)\n\t"
		"movq %%rax, 16(%%r15)\n\t"
		"movq %%rbx, 24(%%r15)\n\t"
		"movq %%rcx, 32(%%r15)\n\t"
		"movq %%rdx, 40(%%r15)\n\t"
		"movq %%rsi, 48(%%r15)\n\t"
		"movq %%rdi, 56(%%r15)\n\t"
		"movq %%r8, 64(%%r15)\n\t"
		"movq %%r9, 72(%%r15)\n\t"
		"movq %%r10, 80(%%r15)\n\t"
		"movq %%r11, 88(%%r15)\n\t"
		"movq %%r12, 96(%%r15)\n\t"
		"movq %%r13, 104(%%r15)\n\t"
		"movq %%r14, 112(%%r15)\n\t"
		"movq %%xmm0, 120(%%r15)\n\t"
		"movq %%xmm8, 128(%%r15)\n\t"
		"movq %%xmm15, 136(%%r15)\n\t"
		"cmpl $0, %[avx]\n\t"
		"je 2f\n\t"
		"vextractf128 $1, %%ymm8, %%xmm8\n\t"
		"movq %%xmm8, 144(%%r15)\n\t"
		"vzeroupper\n"
		"2:\n\t"
		: : [outp] "m"(outp), [avx] "m"(avx)
		: "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
		  "r12", "r13", "r14", "r15", "xmm0", "xmm8", "xmm15", "cc", "memory");
	g_clobber_page = 0;
	static const uint64_t want[12] = {
		0x1111111111111111ull, 0x2222222222222222ull, 0x3333333333333333ull,
		0x4444444444444444ull, 0x5555555555555555ull, 0x6666666666666666ull,
		0x7777777777777777ull, 0x8888888888888888ull, 0x9999999999999999ull,
		0xaaaaaaaaaaaaaaaaull, 0xbbbbbbbbbbbbbbbbull, 0xccccccccccccccccull,
	};
	uint64_t bad = 0;
	if (page[1] != 0x5a) bad |= 1;
	if ((out[1] & 0xff) != 1) bad |= 2;                              /* carry */
	for (int i = 0; i < 12; i++) if (out[2 + i] != want[i]) bad |= 1ull << (8 + i);
	if (out[14] != (uint64_t)(uintptr_t)page) bad |= 1ull << 20;     /* r14 */
	if (out[15] != want[0] || out[16] != want[1] || out[17] != want[2]) bad |= 1ull << 21;   /* xmm */
	if (avx && out[18] != want[1]) bad |= 1ull << 22;                /* ymm8's upper half */
	munmap((void *)page, 4096);
	return bad;
}

/* Never returns: a protected page the handler does not claim (it answers 0),
 * which is an unhandled fault and the machine's death, as without a handler. */
ECL_EXPORT uint64_t RunGuestFaultDeclined(void) {
	volatile uint8_t *page = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED) return 0xff;
	if (mprotect((void *)page, 4096, PROT_READ) != 0) return 0xfe;
	page[1] = 0x5a;
	return 0xfd;
}

/* Never returns: the handler loops for ever on this fault, making no system
 * call, for the stop the host asks for from another thread (wbx_stop_guest).
 * RPCS3's texture cache waits inside its fault handler for its renderer, and
 * a wait there that never ended could not be stopped on Windows, where the
 * handler runs inside the host's own (chimera#363). */
ECL_EXPORT uint64_t SpinInFaultHandler(void) {
	volatile uint8_t *page = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED) return 0xff;
	if (mprotect((void *)page, 4096, PROT_READ) != 0) return 0xfe;
	g_spin_page = (uintptr_t)page;
	page[1] = 0x5a;
	return 0xfd;
}

/* Never returns: a call through a null pointer from a guest that owns %fs.
 * The fault is outside the guest's memory and arrives with the guest's thread
 * pointer loaded; the handler must put the host's back before it runs any
 * host C, and end the machine, not the host (2026-10-18). */
ECL_EXPORT uint64_t CallNullWithOwnFs(void) {
	void (*volatile f)(void) = 0;
	f();
	return 0xfd;
}
