/* Savestate corner cases: the round-trip semantics that separate a correct
 * dirty-tracker from a broken one. */
#include "minibox_internal.h"
#include "test_util.h"

static volatile uint8_t *gp(mb_block *b, uintptr_t off) { return (volatile uint8_t *)(b->addr.start + off); }

static mb_block *fresh_rw(uintptr_t size) {
	mb_range a = { 0x36f00000000ull, size };
	mb_block *b = mb_block_new(a);
	mb_block_activate(b);
	mb_range r = { a.start, size };
	mb_block_mmap_fixed(b, r, MB_PROT_RW, true);
	return b;
}

/* The core property: load reverts pages dirtied AFTER the save, and restores
 * pages that were clean at save time back to their sealed baseline. */
static void test_revert_after_save(void) {
	mb_block *b = fresh_rw(0x10000);
	for (int i = 0; i < 0x10000; i++) gp(b, i)[0] = (uint8_t)(i * 7 + 1);  /* baseline content */
	CHECK_EQ(mb_block_seal(b), 0);

	gp(b, 0x0010)[0] = 0xAA;  /* dirty page 0 post-seal */
	gp(b, 0x3abc)[0] = 0xBB;  /* dirty page 3 post-seal */

	membuf st = {0};
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&st), 0);

	gp(b, 0x0010)[0] = 0x11;   /* change saved pages */
	gp(b, 0x3abc)[0] = 0x22;
	gp(b, 0x8000)[0] = 0x33;   /* dirty a page that was CLEAN at save time */

	st.pos = 0;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&st), 0);
	CHECK_EQ(gp(b, 0x0010)[0], 0xAA);
	CHECK_EQ(gp(b, 0x3abc)[0], 0xBB);
	CHECK_EQ(gp(b, 0x8000)[0], (uint8_t)(0x8000 * 7 + 1));  /* reverted to baseline */
	membuf_free(&st);
	mb_block_free(b);
}

/* Invisible pages are excluded from state: their content is NOT saved/restored. */
static void test_invisible_excluded(void) {
	mb_block *b = fresh_rw(0x10000);
	mb_range iv = { b->addr.start + 0x9000, 0x1000 };
	mb_block_mark_invisible(b, iv);
	CHECK_EQ(mb_block_seal(b), 0);

	gp(b, 0x1000)[0] = 0x55;   /* normal page */
	gp(b, 0x9000)[0] = 0x66;   /* invisible page */
	membuf st = {0};
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&st), 0);

	gp(b, 0x1000)[0] = 0x77;
	gp(b, 0x9000)[0] = 0x88;   /* change invisible after save */
	st.pos = 0;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&st), 0);
	CHECK_EQ(gp(b, 0x1000)[0], 0x55);   /* normal page reverted */
	CHECK_EQ(gp(b, 0x9000)[0], 0x88);   /* invisible page NOT reverted */
	membuf_free(&st);
	mb_block_free(b);
}

/* A page zero at seal, written then reverted, comes back zero (ZeroFilled
 * baseline path). */
static void test_zerofilled_baseline(void) {
	mb_block *b = fresh_rw(0x4000);
	/* leave all zero at seal */
	CHECK_EQ(mb_block_seal(b), 0);
	membuf st = {0};
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&st), 0);  /* nothing dirty */
	gp(b, 0x100)[0] = 0x99;
	st.pos = 0;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&st), 0);
	CHECK_EQ(gp(b, 0x100)[0], 0);   /* reverted to zero baseline */
	membuf_free(&st);
	mb_block_free(b);
}

/* Repeated save/load round-trips remain stable. */
static void test_repeated_roundtrip(void) {
	mb_block *b = fresh_rw(0x8000);
	CHECK_EQ(mb_block_seal(b), 0);
	gp(b, 0x10)[0] = 0xAB;
	membuf st = {0};
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&st), 0);
	for (int i = 0; i < 5; i++) {
		gp(b, 0x10)[0] = (uint8_t)i;
		st.pos = 0;
		CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&st), 0);
		CHECK_EQ(gp(b, 0x10)[0], 0xAB);
	}
	membuf_free(&st);
	mb_block_free(b);
}

/* Save before seal is an error. */
static void test_save_before_seal(void) {
	mb_block *b = fresh_rw(0x2000);
	membuf st = {0};
	CHECK(mb_block_save_state(b, membuf_write, (uintptr_t)&st) != 0);
	membuf_free(&st);
	mb_block_free(b);
}

/* A state from a machine with a DIFFERENT sealed baseline is refused.
 *
 * It cannot be loaded correctly and the failure does not land where the mistake
 * is: a state carries only the pages dirtied since the seal, and every clean
 * page is read back from the baseline - so a state from another baseline
 * assembles a machine out of two. It runs, and it dies later somewhere with
 * nothing to connect the two. Refusing is what lets a caller whose states are a
 * cache know to throw them away. */
static void test_foreign_state_refused(void) {
	/* The baseline's identity is WHICH pages the machine touched on its way to
	 * being sealed, so two machines differ by having touched different ones -
	 * which is exactly how two boots of one core can differ. */
	mb_block *a = fresh_rw(0x10000);
	for (int i = 0; i < 0x8000; i++) gp(a, i)[0] = (uint8_t)(i * 7 + 1);
	CHECK_EQ(mb_block_seal(a), 0);
	gp(a, 0x0010)[0] = 0xAA;

	membuf st = {0};
	CHECK_EQ(mb_block_save_state(a, membuf_write, (uintptr_t)&st), 0);
	mb_block_free(a);

	/* same shape, same size, different baseline - which is the whole point:
	 * nothing about the SHAPE says these are different machines */
	mb_block *b = fresh_rw(0x10000);
	for (int i = 0; i < 0xC000; i++) gp(b, i)[0] = (uint8_t)(i * 11 + 3);
	CHECK_EQ(mb_block_seal(b), 0);

	st.pos = 0;
	CHECK(mb_block_load_state(b, membuf_read, (uintptr_t)&st) != 0);
	/* and it is refused rather than half-applied */
	CHECK_EQ(gp(b, 0x0010)[0], (uint8_t)(0x0010 * 11 + 3));

	membuf_free(&st);
	mb_block_free(b);
}

static void run_all(void) {
	RUN(test_revert_after_save);
	RUN(test_invisible_excluded);
	RUN(test_zerofilled_baseline);
	RUN(test_repeated_roundtrip);
	RUN(test_save_before_seal);
	RUN(test_foreign_state_refused);
}
TEST_MAIN()
