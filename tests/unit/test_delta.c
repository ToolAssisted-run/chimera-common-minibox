/* Epochs and deltas: what changed since a MOMENT, rather than since the
 * baseline. Exercises the real SIGSEGV fault handler on Linux - the epoch's
 * pre-image is captured by the same fault that captures the baseline's. */
#include "minibox_internal.h"
#include "test_util.h"
#include <errno.h>

static volatile uint8_t *gp(mb_block *b, uintptr_t off) {
	return (volatile uint8_t *)(b->addr.start + off);
}

/* a sealed block with `size` bytes of RW guest memory */
static mb_block *sealed(uintptr_t size) {
	mb_range a = { 0x36f00000000ull, size };
	mb_block *b = mb_block_new(a);
	mb_block_activate(b);
	mb_range r = { b->addr.start, size };
	mb_block_mmap_fixed(b, r, MB_PROT_RW, true);
	mb_block_seal(b);
	return b;
}

/* the same, somewhere else, for the rare test that needs two live at once */
static mb_block *sealed_at(uintptr_t base, uintptr_t size) {
	mb_range a = { base, size };
	mb_block *b = mb_block_new(a);
	mb_block_activate(b);
	mb_range r = { b->addr.start, size };
	mb_block_mmap_fixed(b, r, MB_PROT_RW, true);
	mb_block_seal(b);
	return b;
}

/* the whole guest range, for comparing one machine against another */
static uint8_t *snapshot(mb_block *b, uintptr_t size) {
	uint8_t *out = malloc(size);
	memcpy(out, (const void *)b->addr.start, size);
	return out;
}

/* An epoch reports the pages written during it, and no others. */
static void test_epoch_tracks_what_changed(void) {
	mb_block *b = sealed(0x20000);           /* 32 pages */
	gp(b, 0x1000)[0] = 1;                    /* dirty page 1 BEFORE the epoch */

	CHECK_EQ(mb_block_epoch_begin(b), 0);
	CHECK_EQ(mb_block_epoch_page_count(b), 0);

	gp(b, 0x3000)[0] = 7;                    /* page 3 */
	gp(b, 0x3800)[0] = 8;                    /* page 3 again - still one page */
	gp(b, 0x9000)[0] = 9;                    /* page 9 */
	CHECK_EQ(mb_block_epoch_page_count(b), 2);

	/* a page already dirty against the baseline is still tracked by the epoch:
	 * the two questions are independent, which is the whole point */
	gp(b, 0x1000)[0] = 2;
	CHECK_EQ(mb_block_epoch_page_count(b), 3);

	mb_block_free(b);
}

/* A forward delta carries the machine from the epoch's start to its end. */
static void test_forward_delta_reproduces(void) {
	const uintptr_t SIZE = 0x20000;
	mb_block *b = sealed(SIZE);
	for (uintptr_t i = 0; i < SIZE; i += 0x1000) gp(b, i)[0] = (uint8_t)(i >> 12);

	CHECK_EQ(mb_block_epoch_begin(b), 0);
	uint8_t *before = snapshot(b, SIZE);

	gp(b, 0x2000)[0] = 0xAA;
	gp(b, 0x5000)[3] = 0xBB;
	uint8_t *after = snapshot(b, SIZE);

	membuf fwd = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&fwd), 0);

	/* put the machine back to the epoch's start by hand, then let the delta
	 * carry it forward again */
	memcpy((void *)b->addr.start, before, SIZE);
	CHECK(memcmp((const void *)b->addr.start, after, SIZE) != 0);
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&fwd), 0);
	CHECK(memcmp((const void *)b->addr.start, after, SIZE) == 0);

	membuf_free(&fwd);
	free(before); free(after);
	mb_block_free(b);
}

/* A reverse delta carries it back - this is what stepping back a frame is. */
static void test_reverse_delta_returns(void) {
	const uintptr_t SIZE = 0x20000;
	mb_block *b = sealed(SIZE);
	for (uintptr_t i = 0; i < SIZE; i += 0x1000) gp(b, i)[0] = (uint8_t)(i >> 12);

	CHECK_EQ(mb_block_epoch_begin(b), 0);
	uint8_t *before = snapshot(b, SIZE);

	gp(b, 0x2000)[0] = 0xAA;
	gp(b, 0x7000)[9] = 0xCC;

	membuf rev = { 0 };
	CHECK_EQ(mb_block_delta_save(b, false, membuf_write, (uintptr_t)&rev), 0);
	CHECK(memcmp((const void *)b->addr.start, before, SIZE) != 0);
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&rev), 0);
	CHECK(memcmp((const void *)b->addr.start, before, SIZE) == 0);

	membuf_free(&rev);
	free(before);
	mb_block_free(b);
}

/* A chain of per-epoch deltas equals the run. This is the greenzone's claim:
 * anchor plus deltas is the same machine as one that never stopped. */
static void test_delta_chain_equals_the_run(void) {
	const uintptr_t SIZE = 0x20000;
	const int STEPS = 8;
	mb_block *b = sealed(SIZE);

	uint8_t *anchor = snapshot(b, SIZE);
	membuf steps[STEPS];
	uint8_t *expected[STEPS];
	for (int s = 0; s < STEPS; s++) {
		CHECK_EQ(mb_block_epoch_begin(b), 0);
		/* a different page each step, plus one page written every step */
		gp(b, (uintptr_t)(s + 2) << 12)[s] = (uint8_t)(0x10 + s);
		gp(b, 0x1000)[s] = (uint8_t)(0x80 + s);
		steps[s] = (membuf){ 0 };
		CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&steps[s]), 0);
		expected[s] = snapshot(b, SIZE);
	}

	/* replay from the anchor through every delta */
	memcpy((void *)b->addr.start, anchor, SIZE);
	for (int s = 0; s < STEPS; s++) {
		CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&steps[s]), 0);
		CHECK(memcmp((const void *)b->addr.start, expected[s], SIZE) == 0);
	}

	for (int s = 0; s < STEPS; s++) { membuf_free(&steps[s]); free(expected[s]); }
	free(anchor);
	mb_block_free(b);
}

/* A delta carries the allocation map, not just the bytes: a page mapped during
 * the epoch has to exist on the other side. */
static void test_delta_carries_allocation(void) {
	mb_block *b = sealed(0x20000);
	mb_range gone = { b->addr.start + 0x4000, 0x1000 };
	CHECK_EQ(mb_block_munmap(b, gone), 0);
	CHECK_EQ(mb_block_page_info(b, 4) & 0x3f, 0);   /* free */

	CHECK_EQ(mb_block_epoch_begin(b), 0);
	CHECK_EQ(mb_block_mmap_fixed(b, gone, MB_PROT_RW, false), 0);
	CHECK(((mb_block_page_info(b, 4) & 0x3f) != 0));

	membuf fwd = { 0 }, rev = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&fwd), 0);
	CHECK_EQ(mb_block_delta_save(b, false, membuf_write, (uintptr_t)&rev), 0);

	/* the reverse delta takes the mapping away again */
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&rev), 0);
	CHECK_EQ(mb_block_page_info(b, 4) & 0x3f, 0);
	/* and the forward one brings it back */
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&fwd), 0);
	CHECK(((mb_block_page_info(b, 4) & 0x3f) != 0));

	membuf_free(&fwd); membuf_free(&rev);
	mb_block_free(b);
}

/* A delta of one machine is refused by another shape of machine, and rubbish
 * is refused outright, rather than being applied to produce nonsense. */
static void test_delta_refusals(void) {
	mb_block *b = sealed(0x20000);
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	gp(b, 0x2000)[0] = 1;
	membuf d = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&d), 0);
	mb_block_free(b);

	mb_block *other = sealed(0x10000);   /* half the pages */
	d.pos = 0;
	CHECK_EQ(mb_block_delta_apply(other, membuf_read, (uintptr_t)&d), -EINVAL);

	membuf junk = { 0 };
	const char *nonsense = "not a delta at all, not even close";
	membuf_write((uintptr_t)&junk, (const uint8_t *)nonsense, 34);
	CHECK_EQ(mb_block_delta_apply(other, membuf_read, (uintptr_t)&junk), -EINVAL);

	membuf_free(&d); membuf_free(&junk);
	mb_block_free(other);
}

/* Saving a delta with no epoch open is a mistake, not a silent empty delta. */
static void test_delta_needs_an_epoch(void) {
	mb_block *b = sealed(0x10000);
	membuf d = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&d), -EINVAL);
	membuf_free(&d);
	mb_block_free(b);
}

/* A full savestate still works after deltas have moved the machine: applying a
 * delta marks what it wrote, so a later state carries it. */
static void test_full_state_after_delta(void) {
	const uintptr_t SIZE = 0x20000;
	mb_block *b = sealed(SIZE);
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	gp(b, 0x6000)[0] = 0x5A;
	membuf fwd = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&fwd), 0);

	uint8_t *expected = snapshot(b, SIZE);
	membuf full = { 0 };
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&full), 0);

	/* scribble, then put the whole machine back from the full state */
	gp(b, 0x6000)[0] = 0x11;
	gp(b, 0x8000)[0] = 0x22;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&full), 0);
	CHECK(memcmp((const void *)b->addr.start, expected, SIZE) == 0);

	membuf_free(&fwd); membuf_free(&full); free(expected);
	mb_block_free(b);
}


/* ---- composition ----
 *
 * Thinning a history means merging adjacent deltas, so what composition has to
 * be is not "close enough" but exactly what applying the pair does.
 */

/* The claim, on the one case that can go wrong quietly: a page both deltas
 * wrote. The later value has to win, in the composed delta as in the run. */
static void test_compose_equals_applying_both(void) {
	const uintptr_t SIZE = 0x20000;
	mb_block *b = sealed(SIZE);
	for (uintptr_t i = 0; i < SIZE; i += 0x1000) gp(b, i)[0] = (uint8_t)(i >> 12);

	membuf anchor = { 0 };
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&anchor), 0);

	membuf first = { 0 }, second = { 0 }, both = { 0 };
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	gp(b, 0x2000)[0] = 0xAA;                 /* only the first touches this */
	gp(b, 0x5000)[0] = 0x11;                 /* and both touch this one */
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&first), 0);

	CHECK_EQ(mb_block_epoch_begin(b), 0);
	gp(b, 0x5000)[0] = 0x22;                 /* the value that must survive */
	gp(b, 0x7000)[0] = 0xBB;                 /* only the second touches this */
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&second), 0);
	uint8_t *after = snapshot(b, SIZE);

	CHECK_EQ(mb_block_delta_compose(membuf_read, (uintptr_t)&first,
	                                membuf_read, (uintptr_t)&second,
	                                membuf_write, (uintptr_t)&both), 0);
	CHECK(both.len < first.len + second.len);   /* the shared page is carried once */

	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&anchor), 0);
	CHECK(memcmp((const void *)b->addr.start, after, SIZE) != 0);
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&both), 0);
	CHECK(memcmp((const void *)b->addr.start, after, SIZE) == 0);
	CHECK_EQ(gp(b, 0x5000)[0], 0x22);

	membuf_free(&anchor); membuf_free(&first); membuf_free(&second); membuf_free(&both);
	free(after);
	mb_block_free(b);
}

/* What thinning really does: compose, then compose the results, until one
 * delta spans the run. A merge that were only correct once would pass the test
 * above and fail here. */
static void test_composing_a_chain_down_to_one(void) {
	const uintptr_t SIZE = 0x20000;
	const int STEPS = 8;
	mb_block *b = sealed(SIZE);
	for (uintptr_t i = 0; i < SIZE; i += 0x1000) gp(b, i)[0] = (uint8_t)(i >> 12);

	membuf anchor = { 0 };
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&anchor), 0);

	membuf link[STEPS];
	for (int s = 0; s < STEPS; s++) {
		CHECK_EQ(mb_block_epoch_begin(b), 0);
		gp(b, (uintptr_t)(s + 2) << 12)[s] = (uint8_t)(0x10 + s);   /* a page of its own */
		gp(b, 0x1000)[s] = (uint8_t)(0x80 + s);                     /* and the page they all share */
		link[s] = (membuf){ 0 };
		CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&link[s]), 0);
	}
	uint8_t *after = snapshot(b, SIZE);

	for (int n = STEPS; n > 1; n /= 2) {
		for (int i = 0; i < n; i += 2) {
			membuf merged = { 0 };
			CHECK_EQ(mb_block_delta_compose(membuf_read, (uintptr_t)&link[i],
			                                membuf_read, (uintptr_t)&link[i + 1],
			                                membuf_write, (uintptr_t)&merged), 0);
			membuf_free(&link[i]); membuf_free(&link[i + 1]);
			link[i / 2] = merged;
		}
	}

	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&anchor), 0);
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&link[0]), 0);
	CHECK(memcmp((const void *)b->addr.start, after, SIZE) == 0);

	membuf_free(&anchor); membuf_free(&link[0]); free(after);
	mb_block_free(b);
}

/* Composition carries the allocation map with the same rule as the bytes: a
 * page mapped by one delta and unmapped by the next is unmapped, and the
 * composed delta has to say so or it lands on a differently shaped machine. */
static void test_compose_carries_allocation(void) {
	const uintptr_t SIZE = 0x20000;
	mb_block *b = sealed(SIZE);
	mb_range page4 = { b->addr.start + 0x4000, 0x1000 };
	mb_range page6 = { b->addr.start + 0x6000, 0x1000 };
	CHECK_EQ(mb_block_munmap(b, page4), 0);

	membuf anchor = { 0 };
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&anchor), 0);

	membuf first = { 0 }, second = { 0 }, both = { 0 };
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	CHECK_EQ(mb_block_mmap_fixed(b, page4, MB_PROT_RW, false), 0);   /* comes back */
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&first), 0);

	CHECK_EQ(mb_block_epoch_begin(b), 0);
	CHECK_EQ(mb_block_munmap(b, page6), 0);                          /* and another goes */
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&second), 0);

	CHECK_EQ(mb_block_delta_compose(membuf_read, (uintptr_t)&first,
	                                membuf_read, (uintptr_t)&second,
	                                membuf_write, (uintptr_t)&both), 0);

	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&anchor), 0);
	CHECK_EQ(mb_block_page_info(b, 4) & 0x3f, 0);                    /* free, as the anchor left it */
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&both), 0);
	CHECK(((mb_block_page_info(b, 4) & 0x3f) != 0));                 /* the first mapped it */
	CHECK_EQ(mb_block_page_info(b, 6) & 0x3f, 0);                    /* the second freed it */

	membuf_free(&anchor); membuf_free(&first); membuf_free(&second); membuf_free(&both);
	mb_block_free(b);
}

/* Two deltas of different machines do not compose into anything. */
static void test_compose_refuses_a_foreign_delta(void) {
	mb_block *small = sealed(0x20000);
	mb_block *big = sealed_at(0x37000000000ull, 0x40000);
	membuf a = { 0 }, c = { 0 }, out = { 0 };

	CHECK_EQ(mb_block_epoch_begin(small), 0);
	gp(small, 0x2000)[0] = 1;
	CHECK_EQ(mb_block_delta_save(small, true, membuf_write, (uintptr_t)&a), 0);
	CHECK_EQ(mb_block_epoch_begin(big), 0);
	gp(big, 0x2000)[0] = 1;
	CHECK_EQ(mb_block_delta_save(big, true, membuf_write, (uintptr_t)&c), 0);

	CHECK(mb_block_delta_compose(membuf_read, (uintptr_t)&a, membuf_read, (uintptr_t)&c,
	                             membuf_write, (uintptr_t)&out) != 0);

	membuf_free(&a); membuf_free(&c); membuf_free(&out);
	mb_block_free(small); mb_block_free(big);
}

static void run_all(void) {
	test_epoch_tracks_what_changed();
	test_forward_delta_reproduces();
	test_reverse_delta_returns();
	test_delta_chain_equals_the_run();
	test_delta_carries_allocation();
	test_delta_refusals();
	test_delta_needs_an_epoch();
	test_full_state_after_delta();
	test_compose_equals_applying_both();
	test_composing_a_chain_down_to_one();
	test_compose_carries_allocation();
	test_compose_refuses_a_foreign_delta();
}

TEST_MAIN()
