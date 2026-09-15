#define _GNU_SOURCE /* nanosleep: this file is compiled -std=c11 */
/* A whole machine taken WHILE IT RUNS, and the one property that matters:
 * the bytes are the bytes of the moment it was asked for.
 *
 * mb_block_state_plan holds the pages a state will carry and lets somebody else
 * copy them - another thread, or the fault handler when the guest writes one
 * first. The state that comes out has to be the state mb_block_save_state would
 * have written at the instant of the plan, whoever ended up doing the copying
 * and in whatever order. Everything here is that sentence, taken apart.
 */
#include "minibox_internal.h"
#include "test_util.h"

#include <stdlib.h>
#include <string.h>

/* One thread, portably: the point of this file is that a state can be filled
 * from somewhere else while the machine runs, and "somewhere else" has to mean
 * the same thing on both platforms. Windows is where the fault handler is a
 * vectored exception handler and where a guest stack may not be held at all,
 * so it is the half that most needs running. */
#ifdef _WIN32
#include <windows.h>
typedef HANDLE mb_test_thread;
static DWORD WINAPI mb_test_trampoline(LPVOID ud);
#define MB_TEST_THREAD_FN(name, arg) static void *name(void *arg)
static void *(*g_test_body)(void *);
static DWORD WINAPI mb_test_trampoline(LPVOID ud) { g_test_body(ud); return 0; }
static int mb_test_start(mb_test_thread *t, void *(*fn)(void *), void *ud) {
	g_test_body = fn;
	*t = CreateThread(NULL, 0, mb_test_trampoline, ud, 0, NULL);
	return *t == NULL ? -1 : 0;
}
static int mb_test_join(mb_test_thread t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); return 0; }
#else
#include <pthread.h>
typedef pthread_t mb_test_thread;
#define MB_TEST_THREAD_FN(name, arg) static void *name(void *arg)
static int mb_test_start(mb_test_thread *t, void *(*fn)(void *), void *ud) { return pthread_create(t, NULL, fn, ud); }
static int mb_test_join(mb_test_thread t) { return pthread_join(t, NULL); }
#endif

static volatile uint8_t *gp(mb_block *b, uintptr_t off) { return (volatile uint8_t *)(b->addr.start + off); }

static mb_block *fresh_rw(uintptr_t size) {
	mb_range a = { 0x36f00000000ull, size };
	mb_block *b = mb_block_new(a);
	mb_block_activate(b);
	mb_range r = { a.start, size };
	mb_block_mmap_fixed(b, r, MB_PROT_RW, true);
	return b;
}

/* A machine that has been running: some of it written since the seal. */
static mb_block *running(uintptr_t size) {
	mb_block *b = fresh_rw(size);
	for (uintptr_t i = 0; i < size; i += 64) gp(b, i)[0] = (uint8_t)(i * 7 + 1);
	CHECK_EQ(mb_block_seal(b), 0);
	for (uintptr_t i = 0; i < size / 2; i += MB_PAGESIZE) gp(b, i)[0] = (uint8_t)(i / MB_PAGESIZE);
	return b;
}

/* Nobody touches it while it is filled: the planned state and the written one
 * must be the same bytes. */
static void test_plan_matches_save(void) {
	mb_block *b = running(0x80000);

	membuf st = {0};
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&st), 0);

	const size_t size = mb_block_state_size(b);
	CHECK_EQ(size, st.len);
	uint8_t *dest = (uint8_t *)calloc(1, size ? size : 1);
	CHECK(dest != NULL);
	CHECK(mb_block_state_plan(b, dest) != 0);
	CHECK(mb_block_plan_count(b) > 0);
	CHECK_EQ(mb_block_plan_finish(b), 0);
	CHECK_EQ(memcmp(dest, st.buf, size), 0);

	free(dest);
	membuf_free(&st);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* The machine runs while the state is being filled - which is the whole point -
 * and every page it writes must still come out as it was when the plan was
 * made, not as the writes left it. */
static void test_writes_during_a_plan(void) {
	mb_block *b = running(0x80000);

	membuf before = {0};
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&before), 0);

	const size_t size = mb_block_state_size(b);
	uint8_t *dest = (uint8_t *)calloc(1, size);
	CHECK(dest != NULL);
	CHECK(mb_block_state_plan(b, dest) != 0);

	/* the guest runs: it writes over every page the state is carrying */
	for (uintptr_t i = 0; i < 0x40000; i += MB_PAGESIZE) gp(b, i)[0] = 0xEE;
	CHECK_EQ(mb_block_plan_finish(b), 0);

	CHECK_EQ(memcmp(dest, before.buf, size), 0);
	/* and the machine really did change */
	CHECK_EQ(gp(b, 0)[0], 0xEE);

	free(dest);
	membuf_free(&before);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* A state filled by a THREAD while the machine runs, which is how it is meant
 * to be used: the copier and the fault handler race for every page, and the
 * result must not depend on who wins. */
struct filler { mb_block *b; volatile int go; };

MB_TEST_THREAD_FN(fill_thread, ud) {
	struct filler *f = (struct filler *)ud;
	while (!f->go) { }
	const size_t n = mb_block_plan_count(f->b);
	/* a page at a time, so the racing is as fine-grained as it can be */
	for (size_t i = 0; i < n; i++) mb_block_plan_fill(f->b, i, i + 1);
	return NULL;
}

static void test_filled_by_a_thread(void) {
	for (int round = 0; round < 8; round++) {
		mb_block *b = running(0x100000);

		membuf before = {0};
		CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&before), 0);

		const size_t size = mb_block_state_size(b);
		uint8_t *dest = (uint8_t *)calloc(1, size);
		CHECK(dest != NULL);
		CHECK(mb_block_state_plan(b, dest) != 0);

		struct filler f = { b, 0 };
		mb_test_thread t;
		CHECK_EQ(mb_test_start(&t, fill_thread, &f), 0);
		f.go = 1;
		/* the machine runs at the same time, writing the same pages */
		for (uintptr_t i = 0; i < 0x80000; i += MB_PAGESIZE) gp(b, i)[0] = (uint8_t)(0xA0 + round);
		CHECK_EQ(mb_test_join(t), 0);
		CHECK_EQ(mb_block_plan_finish(b), 0);

		CHECK_EQ(memcmp(dest, before.buf, size), 0);
		free(dest);
		membuf_free(&before);
		CHECK(mb_block_maps_consistent(b));
		mb_block_free(b);
	}
}

/* What comes out of a plan is a state: it loads, and it puts the machine back
 * where it was when the plan was made. */
static void test_a_planned_state_loads(void) {
	mb_block *b = running(0x80000);
	const uint8_t was = gp(b, 0x1000)[0];

	const size_t size = mb_block_state_size(b);
	uint8_t *dest = (uint8_t *)calloc(1, size);
	CHECK(dest != NULL);
	CHECK(mb_block_state_plan(b, dest) != 0);
	for (uintptr_t i = 0; i < 0x40000; i += MB_PAGESIZE) gp(b, i)[0] = 0x5C;
	CHECK_EQ(mb_block_plan_finish(b), 0);

	membuf st = { dest, size, size, 0 };
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&st), 0);
	CHECK_EQ(gp(b, 0x1000)[0], was);
	CHECK_EQ(gp(b, 0)[0], 0);

	free(dest);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* An epoch and a plan hold the same pages for different reasons, and one fault
 * has to serve both: the delta must still describe what the frame did. */
static void test_an_epoch_across_a_plan(void) {
	mb_block *b = running(0x80000);

	mb_block_epoch_begin(b);
	gp(b, 0x2000)[0] = 0x71;              /* written before the plan */

	const size_t size = mb_block_state_size(b);
	uint8_t *dest = (uint8_t *)calloc(1, size);
	CHECK(dest != NULL);
	CHECK(mb_block_state_plan(b, dest) != 0);
	gp(b, 0x5000)[0] = 0x72;              /* and during it */
	CHECK_EQ(mb_block_plan_finish(b), 0);

	membuf delta = {0};
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&delta), 0);

	/* both pages come back when the delta is applied to the machine as it was */
	gp(b, 0x2000)[0] = 0;
	gp(b, 0x5000)[0] = 0;
	delta.pos = 0;
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&delta), 0);
	CHECK_EQ(gp(b, 0x2000)[0], 0x71);
	CHECK_EQ(gp(b, 0x5000)[0], 0x72);

	free(dest);
	membuf_free(&delta);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* Memory given back while a state is being taken. munmap and MADV_DONTNEED zero
 * pages through the mirror, which never faults, so nothing told the plan: the
 * state kept the zeros instead of what malloc had there (chimera issue #68). */
static void test_an_unmap_during_a_plan(void) {
	for (int advise = 0; advise < 2; advise++) {
		mb_block *b = running(0x80000);
		membuf before = {0};
		CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&before), 0);
		const size_t size = mb_block_state_size(b);
		uint8_t *dest = (uint8_t *)calloc(1, size);
		CHECK(dest != NULL);
		CHECK(mb_block_state_plan(b, dest) != 0);

		mb_range r = { b->addr.start + 0x10000, 0x8000 };
		if (advise) CHECK_EQ(mb_block_madvise_dontneed(b, r), 0);
		else CHECK_EQ(mb_block_munmap(b, r), 0);
		CHECK_EQ(mb_block_plan_finish(b), 0);

		CHECK_EQ(memcmp(dest, before.buf, size), 0);
		free(dest);
		membuf_free(&before);
		CHECK(mb_block_maps_consistent(b));
		mb_block_free(b);
	}
}

/* The host writing into the machine while a state is being taken - the same
 * mirror, the same silence. */
static void test_an_external_copy_during_a_plan(void) {
	mb_block *b = running(0x80000);
	membuf before = {0};
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&before), 0);
	const size_t size = mb_block_state_size(b);
	uint8_t *dest = (uint8_t *)calloc(1, size);
	CHECK(dest != NULL);
	CHECK(mb_block_state_plan(b, dest) != 0);

	uint8_t junk[0x3000];
	memset(junk, 0xD7, sizeof junk);
	CHECK_EQ(mb_block_copy_from_external(b, junk, b->addr.start + 0x1800, sizeof junk), 0);
	CHECK_EQ(mb_block_plan_finish(b), 0);

	CHECK_EQ(memcmp(dest, before.buf, size), 0);
	CHECK_EQ(gp(b, 0x2000)[0], 0xD7);
	free(dest);
	membuf_free(&before);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* An older state loaded while a newer one is still being taken: the load
 * rewrites the machine through the mirror, and the newer state must still be
 * the machine it was asked for, not the one being loaded. */
static void test_a_load_during_a_plan(void) {
	mb_block *b = running(0x80000);
	membuf older = {0};
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&older), 0);
	for (uintptr_t i = 0; i < 0x60000; i += MB_PAGESIZE) gp(b, i)[1] = (uint8_t)(0x30 + (i >> 12));

	membuf newer = {0};
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&newer), 0);
	const size_t size = mb_block_state_size(b);
	uint8_t *dest = (uint8_t *)calloc(1, size);
	CHECK(dest != NULL);
	CHECK(mb_block_state_plan(b, dest) != 0);

	older.pos = 0;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&older), 0);
	/* the load finishes the plan itself before it rewrites anything */
	CHECK_EQ(mb_block_plan_count(b), 0);

	CHECK_EQ(memcmp(dest, newer.buf, size), 0);
	free(dest);
	membuf_free(&older);
	membuf_free(&newer);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* The race itself, made to happen: a page somebody is already copying (held at
 * 2). A writer used to take the hold and change the page at once, in the middle
 * of that copy. It has to wait until the copy is done - so the thread standing
 * in for the copier says it has finished BEFORE it lets go, and the writer must
 * see that when it returns. */
struct releaser { mb_block *b; size_t pi; volatile int started; volatile int finished; };

#ifdef _WIN32
static void test_sleep_ms(int ms) { Sleep((DWORD)ms); }
#else
#include <time.h>
static void test_sleep_ms(int ms) { struct timespec ts = { ms / 1000, (long)ms % 1000 * 1000000L }; nanosleep(&ts, NULL); }
#endif

MB_TEST_THREAD_FN(release_thread, ud) {
	struct releaser *r = (struct releaser *)ud;
	r->started = 1;
	test_sleep_ms(60);
	r->finished = 1;
	r->b->pages[r->pi].plan_hold = 0;   /* the copy that was in progress is done */
	return NULL;
}

static void test_a_writer_waits_out_a_copy(void) {
	mb_block *b = running(0x80000);
	const size_t size = mb_block_state_size(b);
	uint8_t *dest = (uint8_t *)calloc(1, size);
	CHECK(dest != NULL);
	CHECK(mb_block_state_plan(b, dest) != 0);

	const size_t pi = b->plan_list[0];
	b->pages[pi].plan_hold = 2;         /* somebody else is copying it */
	struct releaser r = { b, pi, 0, 0 };
	mb_test_thread t;
	CHECK_EQ(mb_test_start(&t, release_thread, &r), 0);
	while (!r.started) { }

	mb_block_plan_capture(b, pi);       /* a writer about to change the page */
	CHECK(r.finished);                  /* it did not return while the copy was in progress */
	CHECK_EQ(mb_test_join(t), 0);

	CHECK_EQ(mb_block_plan_finish(b), 0);
	free(dest);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

static void run_all(void) {
	RUN(test_plan_matches_save);
	RUN(test_writes_during_a_plan);
	RUN(test_filled_by_a_thread);
	RUN(test_a_planned_state_loads);
	RUN(test_an_epoch_across_a_plan);
	RUN(test_an_unmap_during_a_plan);
	RUN(test_an_external_copy_during_a_plan);
	RUN(test_a_load_during_a_plan);
	RUN(test_a_writer_waits_out_a_copy);
}

TEST_MAIN()
