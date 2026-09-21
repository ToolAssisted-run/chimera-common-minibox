#define _GNU_SOURCE   /* clock_gettime under -std=c11 */
/* The fault handler with more than one thread in it.
 *
 * A frame's delta is built from what the fault handler records: the first write
 * to each held page faults, and trip() marks the page written for the open
 * epoch - a bit in epoch_bits, a count in epoch_ndirty, a bit in unheld_bits
 * so the next epoch holds it again. One guest thread faulting on its own is
 * the case run-wbx exercises and the case every existing test exercises. It
 * is not the case Chimera runs: a GPU driver thread writes into guest memory
 * while the guest runs, greenzone helper threads and the background state
 * copier run beside it, and two of them can fault on two pages of the same
 * block at the same moment. A bitmap word holds sixty-four pages, so two
 * faults on neighbouring pages are two read-modify-writes of ONE word, and a
 * plain |= loses one of them. A lost epoch bit is a page the delta does not
 * carry: a silent wrong machine on a later seek, not a crash.
 *
 * So N threads each write their OWN pages of one block, interleaved so that
 * every thread's pages share bitmap words with every other's, inside one
 * epoch, many times over; after each round the epoch must have counted
 * exactly the pages written, and the bitmap must hold exactly those bits.
 *
 * Watched failing on the code before the tracking lock, on both hosts. This
 * runs on Linux as well as Windows, and it fails on Linux too: sigaction's
 * sa_mask blocks SIGSEGV for the THREAD that is in the handler, not for the
 * process, so two threads run handler_inner concurrently exactly as two
 * threads run the vectored handler on Windows. The Linux handler serialises
 * nothing between threads; what it has that the Windows one lacked is the
 * per-thread depth guard against re-entry on ONE thread, which is a
 * different defect. Windows is still the host that matters, because it is
 * the one users run with driver threads. */
#include "minibox_internal.h"
#include "test_util.h"
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
typedef HANDLE mb_test_thread;
static void *(*g_test_body)(void *);
static DWORD WINAPI mb_test_trampoline(LPVOID ud) { g_test_body(ud); return 0; }
static int mb_test_start(mb_test_thread *t, void *(*fn)(void *), void *ud) {
	g_test_body = fn;
	*t = CreateThread(NULL, 0, mb_test_trampoline, ud, 0, NULL);
	return *t == NULL ? -1 : 0;
}
static int mb_test_join(mb_test_thread t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); return 0; }
static double now_ns(void) {
	LARGE_INTEGER f, c;
	QueryPerformanceFrequency(&f);
	QueryPerformanceCounter(&c);
	return (double)c.QuadPart * 1e9 / (double)f.QuadPart;
}
#else
#include <pthread.h>
#include <time.h>
typedef pthread_t mb_test_thread;
static int mb_test_start(mb_test_thread *t, void *(*fn)(void *), void *ud) { return pthread_create(t, NULL, fn, ud); }
static int mb_test_join(mb_test_thread t) { return pthread_join(t, NULL); }
static double now_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}
#endif

static inline void cpu_relax(void) {
#if defined(__x86_64__) || defined(__i386__)
	__builtin_ia32_pause();
#endif
}

static volatile uint8_t *gp(mb_block *b, uintptr_t off) {
	return (volatile uint8_t *)(b->addr.start + off);
}

/* a sealed block with `size` bytes of RW guest memory, every page dirtied
 * once so that an epoch has to HOLD it (a clean page is read-only already) */
static mb_block *sealed_and_dirty(uintptr_t size) {
	mb_range a = { 0x36f00000000ull, size };
	mb_block *b = mb_block_new(a);
	mb_block_activate(b);
	mb_range r = { b->addr.start, size };
	mb_block_mmap_fixed(b, r, MB_PROT_RW, true);
	mb_block_seal(b);
	for (uintptr_t off = 0; off < size; off += MB_PAGESIZE) gp(b, off)[0] = 1;
	return b;
}

static size_t popcount_words(const uint64_t *w, size_t n) {
	size_t c = 0;
	for (size_t i = 0; i < n; i++) c += (size_t)__builtin_popcountll(w[i]);
	return c;
}

/* ---- the concurrent-fault leg ---------------------------------------------- */

#define NTHREADS         8
#define PAGES_PER_THREAD 64
#define NPAGES           (NTHREADS * PAGES_PER_THREAD)

struct writer {
	mb_block *b;
	int index;
	volatile int *round;       /* bumped by the main thread to start a round */
	volatile int *done;        /* bumped by each writer when its pages are written */
	volatile int *stop;
	int rounds_seen;
};

static void *writer_thread(void *ud) {
	struct writer *w = (struct writer *)ud;
	for (;;) {
		while (__atomic_load_n(w->round, __ATOMIC_ACQUIRE) == w->rounds_seen
		       && !__atomic_load_n(w->stop, __ATOMIC_ACQUIRE)) cpu_relax();
		if (__atomic_load_n(w->stop, __ATOMIC_ACQUIRE)) return NULL;
		w->rounds_seen++;
		/* pages index, index+N, index+2N ... : this thread's own pages, each
		 * sharing its bitmap word with every other thread's */
		for (int k = 0; k < PAGES_PER_THREAD; k++) {
			const uintptr_t page = (uintptr_t)(k * NTHREADS + w->index);
			gp(w->b, page << MB_PAGESHIFT)[0] = (uint8_t)(0x10 + w->rounds_seen);
		}
		__atomic_add_fetch(w->done, 1, __ATOMIC_ACQ_REL);
	}
}

static int rounds_wanted(void) {
	const char *e = getenv("MB_TEST_FAULT_ROUNDS");
	int n = e ? atoi(e) : 0;
	return n > 0 ? n : 1500;
}

static void test_concurrent_faults_are_all_counted(void) {
	mb_block *b = sealed_and_dirty((uintptr_t)NPAGES << MB_PAGESHIFT);
	volatile int round = 0, done = 0, stop = 0;
	struct writer ws[NTHREADS];
	mb_test_thread ts[NTHREADS];
	for (int i = 0; i < NTHREADS; i++) {
		ws[i].b = b; ws[i].index = i; ws[i].round = &round; ws[i].done = &done; ws[i].stop = &stop;
		ws[i].rounds_seen = 0;
		CHECK_EQ(mb_test_start(&ts[i], writer_thread, &ws[i]), 0);
	}

	const int rounds = rounds_wanted();
	int short_rounds = 0, first_short = -1;
	size_t least_count = NPAGES, least_bits = NPAGES;
	for (int r = 0; r < rounds; r++) {
		CHECK_EQ(mb_block_epoch_begin(b), 0);   /* re-holds every page written last round */
		__atomic_add_fetch(&round, 1, __ATOMIC_ACQ_REL);
		while (__atomic_load_n(&done, __ATOMIC_ACQUIRE) < NTHREADS * (r + 1)) cpu_relax();

		const size_t counted = mb_block_epoch_page_count(b);
		const size_t bits = popcount_words(b->epoch_bits, b->nwords);
		if (counted != NPAGES || bits != NPAGES) {
			short_rounds++;
			if (first_short < 0) first_short = r;
			if (counted < least_count) least_count = counted;
			if (bits < least_bits) least_bits = bits;
		}
	}
	__atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
	for (int i = 0; i < NTHREADS; i++) CHECK_EQ(mb_test_join(ts[i]), 0);

	printf("test_tripguard: %d threads x %d pages x %d rounds (%d faults): %d round(s) short",
	       NTHREADS, PAGES_PER_THREAD, rounds, NPAGES * rounds, short_rounds);
	if (short_rounds)
		printf(" (first at round %d; least seen: count %zu, bits %zu of %d)",
		       first_short, least_count, least_bits, NPAGES);
	printf("\n");
	CHECK_EQ(short_rounds, 0);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* ---- what a fault costs, single-threaded -----------------------------------
 *
 * Not a check: a number, printed, so that a change to the handler's fast path
 * can be weighed. Every page of a block is written once per epoch, so every
 * write is a fault that trips, and the whole write loop is timed. */
static void measure_fault_cost(void) {
	const size_t npages = 4096;
	mb_block *b = sealed_and_dirty(npages << MB_PAGESHIFT);
	const int epochs = 20;
	double total = 0;
	for (int e = 0; e < epochs; e++) {
		CHECK_EQ(mb_block_epoch_begin(b), 0);
		const double t0 = now_ns();
		for (size_t i = 0; i < npages; i++) gp(b, i << MB_PAGESHIFT)[0] = (uint8_t)e;
		total += now_ns() - t0;
		CHECK_EQ(mb_block_epoch_page_count(b), npages);
	}
	printf("test_tripguard: fault cost %.0f ns/fault over %zu faults (one thread)\n",
	       total / (double)(npages * (size_t)epochs), npages * (size_t)epochs);
	mb_block_free(b);
}

static void run_all(void) {
	RUN(measure_fault_cost);
	RUN(test_concurrent_faults_are_all_counted);
}

TEST_MAIN()
