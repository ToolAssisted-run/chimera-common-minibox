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

/* A plan given less room than the state needs refuses before it holds or
 * writes anything; given exactly the room, it plans what save writes. The
 * host plans this way instead of asking the size first, which walked every
 * page once more (2026-10-18). Invisible pages are dirty too, and are not in
 * the count. */
static void test_plan_within_its_room(void) {
	mb_block *b = fresh_rw(0x80000);
	mb_range inv = { b->addr.start + 0x70000, 0x4000 };   /* before the seal, as a guest marks it */
	CHECK_EQ(mb_block_mark_invisible(b, inv), 0);
	for (uintptr_t i = 0; i < 0x80000; i += 64) gp(b, i)[0] = (uint8_t)(i * 7 + 1);
	CHECK_EQ(mb_block_seal(b), 0);
	for (uintptr_t i = 0; i < 0x40000; i += MB_PAGESIZE) gp(b, i)[0] = (uint8_t)(i / MB_PAGESIZE);
	gp(b, 0x70010)[0] = 9;                                 /* written, and in no state */
	membuf st = {0};
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&st), 0);
	const size_t size = mb_block_state_size(b);
	CHECK_EQ(size, st.len);
	uint8_t *dest = (uint8_t *)calloc(1, size + 1);
	CHECK(dest != NULL);
	dest[0] = 0xEE;
	CHECK_EQ(mb_block_state_plan_within(b, dest, size - 1), 0);
	CHECK_EQ(dest[0], 0xEE);                 /* nothing written */
	CHECK(!b->plan_active);                  /* nothing held */
	const size_t at = mb_block_state_plan_within(b, dest, size);
	CHECK(at != 0);
	CHECK_EQ(at + mb_block_plan_count(b) * MB_PAGESIZE, size);
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

/* A plan must not cost the NEXT epoch its holds.
 *
 * This is the order a history takes an anchor in: the state is planned as the
 * frame ends, and the epoch for the next frame opens while somebody else is
 * still copying it. The pages the plan held were mapped writable until then -
 * written since the last epoch, so the next one owed each of them a hold -
 * and holding them for the plan took them off the list that hold is made
 * from. Nothing showed while a page stayed as the plan left it, read-only; the
 * first thing that worked its protection out again after the copy found it
 * dirty, not held, owed to nobody, and mapped it writable. What the guest wrote
 * there was then in no delta.
 *
 * Two things work a protection out again, and both are here: the guest giving
 * a range the protection it already has (RPCS3 does it all day to the pages of
 * its video memory, and Dead or Alive 5 came back from a greenzone restore
 * with four pages of it stale and a PPU thread jumping to address zero), and
 * the plan being finished in the middle of the epoch. */
static void test_a_plan_keeps_the_next_epochs_holds(void) {
	for (int how = 0; how < 2; how++) {
		mb_block *b = running(0x80000);
		const size_t size = mb_block_state_size(b);
		uint8_t *dest = (uint8_t *)calloc(1, size);
		CHECK(dest != NULL);
		CHECK(mb_block_state_plan(b, dest) != 0);       /* the anchor, as the frame ends */
		mb_block_epoch_begin(b);                         /* the next frame's epoch */
		if (how == 0) {
			/* somebody copies the whole state, and the guest then says of a
			 * range what is already true of it */
			CHECK_EQ(mb_block_plan_fill(b, 0, mb_block_plan_count(b)), mb_block_plan_count(b));
			mb_range r = { b->addr.start + 0x2000, 0x4000 };
			CHECK_EQ(mb_block_mprotect(b, r, MB_PROT_RW), 0);
		} else {
			CHECK_EQ(mb_block_plan_finish(b), 0);
		}
		gp(b, 0x3000)[5] = 0x99;                         /* the frame writes */
		if (how == 0) CHECK_EQ(mb_block_plan_finish(b), 0);

		membuf delta = {0};
		CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&delta), 0);
		gp(b, 0x3000)[5] = 0;
		delta.pos = 0;
		CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&delta), 0);
		CHECK_EQ(gp(b, 0x3000)[5], 0x99);                /* the delta knew */

		free(dest);
		membuf_free(&delta);
		CHECK(mb_block_maps_consistent(b));
		mb_block_free(b);
	}
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

/* A page the guest takes every right from while a state still owes it stays
 * without them: the hold takes away writing, not what the guest asked for. It
 * was readable until the copier got to it. A whole host page of them: on a
 * host whose page is larger than the machine's (16 KiB on Apple silicon), one
 * machine page shares its protection with the rest of its host page, and
 * stays readable while they are. */
static void test_a_hold_keeps_the_guests_protection(void) {
	mb_block *b = running(0x80000);
	const uintptr_t host_page = (uintptr_t)mb_group_pages() * MB_PAGESIZE;
	const size_t size = mb_block_state_size(b);
	uint8_t *dest = (uint8_t *)calloc(1, size);
	CHECK(dest != NULL);
	CHECK(mb_block_state_plan(b, dest) != 0);
	mb_range none = { b->addr.start + 0x20000, host_page };
	CHECK_EQ(mb_block_mprotect(b, none, MB_PROT_NONE), 0);
	CHECK(!mb_page_readable(none.start));
	mb_range ro = { b->addr.start + 0x20000 + host_page, host_page };
	CHECK_EQ(mb_block_mprotect(b, ro, MB_PROT_R), 0);
	CHECK(mb_page_readable(ro.start));
	CHECK(mb_block_maps_consistent(b));
	CHECK_EQ(mb_block_plan_finish(b), 0);
	CHECK(!mb_page_readable(none.start));
	free(dest);
	mb_block_free(b);
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
	RUN(test_plan_within_its_room);
	RUN(test_writes_during_a_plan);
	RUN(test_filled_by_a_thread);
	RUN(test_a_planned_state_loads);
	RUN(test_an_epoch_across_a_plan);
	RUN(test_a_plan_keeps_the_next_epochs_holds);
	RUN(test_an_unmap_during_a_plan);
	RUN(test_an_external_copy_during_a_plan);
	RUN(test_a_load_during_a_plan);
	RUN(test_a_writer_waits_out_a_copy);
	RUN(test_a_hold_keeps_the_guests_protection);
}

TEST_MAIN()
