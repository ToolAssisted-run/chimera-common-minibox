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

	CHECK(mb_block_maps_consistent(b));
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
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* A delta applied to a page THIS process never wrote must not turn the
 * delta's bytes into the page's baseline.
 *
 * The page's sealed content is copied aside the first time it changes, and a
 * delta from a history file applied to a machine that had not reached that
 * frame is such a first time. Copied AFTER the delta had overwritten the page,
 * the copy was the delta's bytes, and every later load of a state in which the
 * page was clean put those back instead of the sealed ones. The load here is of
 * the anchor taken before the delta, and it must find the sealed byte. */
static void test_delta_applied_to_a_clean_page_keeps_the_baseline(void) {
	const uintptr_t SIZE = 0x8000;
	mb_block *b = sealed(SIZE);
	/* the delta is made on one machine ... */
	mb_block *other = sealed_at(0x37000000000ull, SIZE);
	gp(other, 0x3000)[0] = 0x11;   /* the sealed byte, on both machines */
	gp(b, 0x3000)[0] = 0x11;
	membuf anchor = { 0 };
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&anchor), 0);
	CHECK_EQ(mb_block_epoch_begin(other), 0);
	gp(other, 0x3000)[0] = 0x22;
	membuf fwd = { 0 };
	CHECK_EQ(mb_block_delta_save(other, true, membuf_write, (uintptr_t)&fwd), 0);
	/* ... and applied to another that never touched the page since sealing. The
	 * two machines have the same layout, which is all a delta checks. */
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&fwd), 0);
	CHECK_EQ(gp(b, 0x3000)[0], 0x22);
	anchor.pos = 0;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&anchor), 0);
	CHECK_EQ(gp(b, 0x3000)[0], 0x11);
	membuf_free(&fwd); membuf_free(&anchor);
	mb_block_free(other);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* After a delta is applied, the pages it brought are watched again: a write
 * to one of them lands in the next delta. Applying used to re-protect the
 * whole arena to guarantee that; now only the pages the delta touched are
 * looked at, and this is what would break if one were missed. */
static void test_delta_apply_leaves_its_pages_watched(void) {
	const uintptr_t SIZE = 0x20000;
	mb_block *b = sealed(SIZE);
	membuf anchor = { 0 };
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&anchor), 0);

	/* a frame that writes a page and maps a new one */
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	gp(b, 0x4000)[0] = 0xAA;
	membuf fwd = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&fwd), 0);

	/* back to the anchor, forward by the delta, then the next frame writes the
	 * same page again and a page beside it */
	anchor.pos = 0;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&anchor), 0);
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&fwd), 0);
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	gp(b, 0x4000)[1] = 0xBB;
	gp(b, 0x5000)[0] = 0xCC;
	CHECK_EQ(mb_block_epoch_page_count(b), 2);
	membuf next = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&next), 0);

	/* and that delta reproduces both writes on a machine that lacks them */
	anchor.pos = 0;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&anchor), 0);
	fwd.pos = 0;
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&fwd), 0);
	CHECK_EQ(gp(b, 0x4000)[1], 0);
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&next), 0);
	CHECK_EQ(gp(b, 0x4000)[0], 0xAA);
	CHECK_EQ(gp(b, 0x4000)[1], 0xBB);
	CHECK_EQ(gp(b, 0x5000)[0], 0xCC);
	membuf_free(&fwd); membuf_free(&next); membuf_free(&anchor);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* A page written frame after frame goes hot: it stops faulting, and every
 * change to it still lands in the delta of the frame that made it. */
static void test_hot_page_still_reports_every_change(void) {
	const uintptr_t SIZE = 0x20000;
	mb_block *b = sealed(SIZE);
	membuf anchor = { 0 };
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&anchor), 0);
	membuf deltas[12];
	memset(deltas, 0, sizeof deltas);
	for (int f = 0; f < 12; f++) {
		CHECK_EQ(mb_block_epoch_begin(b), 0);
		gp(b, 0x4000)[f] = (uint8_t)(f + 1);           /* the hot one */
		if (f == 5) gp(b, 0x9000)[0] = 0x55;            /* a cold one, once */
		CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&deltas[f]), 0);
		CHECK(mb_block_maps_consistent(b));
	}
	CHECK(b->pages[4].hot);
	CHECK(!b->pages[9].hot);
	uint8_t *end = snapshot(b, SIZE);
	/* back to the anchor and forward through every delta: the machine the run
	 * ended on, and the page was in every delta after the hold came off */
	anchor.pos = 0;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&anchor), 0);
	CHECK_EQ(gp(b, 0x4000)[3], 0);
	for (int f = 0; f < 12; f++) CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&deltas[f]), 0);
	CHECK(memcmp((const void *)b->addr.start, end, SIZE) == 0);
	free(end);
	for (int f = 0; f < 12; f++) membuf_free(&deltas[f]);
	membuf_free(&anchor);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* A hot page written with the bytes it already held is not in the delta - the
 * comparison is exact where a fault is not - and a hot page left alone cools
 * and is held again, so its next write is caught by a fault as before. */
static void test_hot_page_cools_and_is_exact(void) {
	const uintptr_t SIZE = 0x20000;
	mb_block *b = sealed(SIZE);
	for (int f = 0; f < 4; f++) {
		CHECK_EQ(mb_block_epoch_begin(b), 0);
		gp(b, 0x4000)[0] = (uint8_t)(f + 1);
		membuf d = { 0 };
		CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&d), 0);
		membuf_free(&d);
	}
	CHECK(b->pages[4].hot);
	/* written, and written back: nothing to report */
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	gp(b, 0x4000)[0] = 0x77;
	gp(b, 0x4000)[0] = 4;
	membuf d = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&d), 0);
	CHECK_EQ(mb_block_epoch_page_count(b), 0);
	membuf_free(&d);
	/* left alone: cools, and its next write faults its way into the delta */
	int frames = 0;
	while (b->pages[4].hot && frames < 64) {
		CHECK_EQ(mb_block_epoch_begin(b), 0);
		membuf e = { 0 };
		CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&e), 0);
		membuf_free(&e);
		frames++;
	}
	CHECK(!b->pages[4].hot);
	CHECK(mb_block_maps_consistent(b));
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	gp(b, 0x4000)[1] = 0x99;
	membuf e = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&e), 0);
	CHECK_EQ(mb_block_epoch_page_count(b), 1);
	membuf_free(&e);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* A state loaded over a hot page, or a delta applied to it, leaves the shadow
 * true: the frame after reports exactly what the guest did and nothing else. */
static void test_hot_page_survives_a_load(void) {
	const uintptr_t SIZE = 0x20000;
	mb_block *b = sealed(SIZE);
	membuf anchor = { 0 };
	for (int f = 0; f < 4; f++) {
		CHECK_EQ(mb_block_epoch_begin(b), 0);
		gp(b, 0x4000)[0] = (uint8_t)(f + 1);
		membuf d = { 0 };
		CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&d), 0);
		membuf_free(&d);
		if (f == 1) CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&anchor), 0);
	}
	CHECK(b->pages[4].hot);
	anchor.pos = 0;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&anchor), 0);
	CHECK_EQ(gp(b, 0x4000)[0], 2);
	CHECK(b->pages[4].hot);
	/* the guest writes the value the page held BEFORE the load: a stale shadow
	 * would call that unchanged */
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	gp(b, 0x4000)[0] = 4;
	membuf d = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&d), 0);
	CHECK_EQ(mb_block_epoch_page_count(b), 1);
	/* and the delta, applied over the loaded state, lands the write */
	anchor.pos = 0;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&anchor), 0);
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&d), 0);
	CHECK_EQ(gp(b, 0x4000)[0], 4);
	membuf_free(&d); membuf_free(&anchor);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* A delta that ends half way leaves a machine to throw away - but a SAFE one:
 * every page it touched is protected as its state now says, so a later write
 * to one of them still faults and still lands in the next delta. Left
 * unprotected, those writes would go unrecorded and the frame after would be
 * short of them, which is a desync a long way from its cause. */
static void test_a_truncated_delta_leaves_pages_watched(void) {
	const uintptr_t SIZE = 0x20000;
	mb_block *b = sealed(SIZE);
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	gp(b, 0x3000)[0] = 0x11;
	gp(b, 0x4000)[0] = 0x22;
	gp(b, 0x5000)[0] = 0x33;
	membuf fwd = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&fwd), 0);

	/* the same delta, cut off inside its last page */
	membuf cut = { 0 };
	membuf_write((uintptr_t)&cut, fwd.buf, fwd.len - 2048);
	CHECK(mb_block_delta_apply(b, membuf_read, (uintptr_t)&cut) != 0);

	/* the machine is not to be trusted, but the tracker's word about it is:
	 * writing every page must produce a delta naming every page */
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	gp(b, 0x3000)[1] = 0xAA;
	gp(b, 0x4000)[1] = 0xBB;
	gp(b, 0x5000)[1] = 0xCC;
	CHECK_EQ(mb_block_epoch_page_count(b), 3);
	CHECK(mb_block_maps_consistent(b));

	membuf_free(&fwd); membuf_free(&cut);
	mb_block_free(b);
}

/* A delta that ends half way has already written PART of a page. That page no
 * longer holds what the baseline holds, so it has to be called dirty - or the
 * next whole state leaves it out, the load after that hands back the sealed
 * bytes, and the machine quietly loses a page nobody wrote to since. */
static void test_a_truncated_delta_dirties_what_it_wrote(void) {
	const uintptr_t SIZE = 0x8000;
	mb_block *b = sealed(SIZE);
	mb_block *other = sealed_at(0x37000000000ull, SIZE);

	/* a delta from a machine that wrote a page this one never has */
	CHECK_EQ(mb_block_epoch_begin(other), 0);
	for (uintptr_t i = 0; i < SIZE; i += 0x1000) gp(other, i)[0] = 0x33;
	membuf fwd = { 0 };
	CHECK_EQ(mb_block_delta_save(other, true, membuf_write, (uintptr_t)&fwd), 0);

	/* cut inside the last page it carries */
	membuf cut = { 0 };
	membuf_write((uintptr_t)&cut, fwd.buf, fwd.len - 2048);
	CHECK(mb_block_delta_apply(b, membuf_read, (uintptr_t)&cut) != 0);

	/* whatever it managed to write, it must own */
	size_t changed = 0;
	for (uintptr_t i = 0; i < SIZE; i += 0x1000) {
		const size_t page = i >> MB_PAGESHIFT;
		if (((const volatile uint8_t *)(b->addr.start + i))[0] != 0x33) continue;
		changed++;
		CHECK((mb_block_page_info(b, page) & 0x80) != 0);
	}
	CHECK(changed != 0);
	CHECK(mb_block_maps_consistent(b));

	membuf_free(&fwd); membuf_free(&cut);
	mb_block_free(other);
	mb_block_free(b);
}

/* The same for a state, and this is the one that bites: a load that ends half
 * way has already put some pages BACK to their sealed content and called them
 * clean. A clean page is watched - held read-only, so its next write faults and
 * is recorded. If the load returns without applying that, the page stays mapped
 * writable while the tracker calls it clean, and every later write to it is
 * invisible: absent from the deltas, absent from the next state, and showing up
 * as a desync a long way from here. */
static void test_a_truncated_state_leaves_pages_watched(void) {
	const uintptr_t SIZE = 0x20000;
	mb_block *b = sealed(SIZE);
	/* a state in which the LATER pages are dirty and the earlier ones are not */
	for (uintptr_t i = 0x8000; i < SIZE; i += 0x1000) gp(b, i)[0] = (uint8_t)(i >> 12);
	membuf whole = { 0 };
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&whole), 0);
	/* then the earlier ones are written too, so loading that state has to put
	 * them back to the baseline and hold them again */
	for (uintptr_t i = 0; i < 0x8000; i += 0x1000) gp(b, i)[0] = 0x5A;

	/* cut inside the page data, which is after both maps: the load gets far
	 * enough to clean the early pages and then fails */
	membuf cut = { 0 };
	membuf_write((uintptr_t)&cut, whole.buf, whole.len - 2048);
	CHECK(mb_block_load_state(b, membuf_read, (uintptr_t)&cut) != 0);

	/* The machine is not to be trusted, but the tracker's word about it is -
	 * and that has to hold from the moment the load returns, not from the next
	 * epoch. The caller is under no obligation to open one: a refused restore
	 * leaves the session running, and a write in that window must still be seen
	 * or the state after it will not carry the page. */
	CHECK(mb_block_maps_consistent(b));
	for (uintptr_t i = 0; i < 0x8000; i += 0x1000) gp(b, i)[2] = 0x77;
	for (uintptr_t i = 0; i < 0x8000; i += 0x1000) {
		CHECK((mb_block_page_info(b, i >> MB_PAGESHIFT) & 0x80) != 0);   /* dirty: the write was seen */
	}

	/* and the same again through an epoch, which is the ordinary path */
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	size_t wrote = 0;
	for (uintptr_t i = 0; i < 0x8000; i += 0x1000) { gp(b, i)[3] = 0x78; wrote++; }
	CHECK_EQ(mb_block_epoch_page_count(b), wrote);

	membuf_free(&whole); membuf_free(&cut);
	mb_block_free(b);
}

/* Backwards is not offered. A frame is reached by loading an anchor and
 * applying the deltas since it, and keeping the other direction possible cost a
 * page copy in the fault handler for every page every frame. Refused outright,
 * because a delta answered with zeros would wipe memory the machine needs. */
static void test_reverse_delta_is_refused(void) {
	mb_block *b = sealed(0x20000);
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	gp(b, 0x2000)[0] = 9;

	membuf rev = { 0 };
	CHECK(mb_block_delta_save(b, false, membuf_write, (uintptr_t)&rev) != 0);
	CHECK_EQ(rev.len, 0);

	/* and forwards still works from the same epoch */
	membuf fwd = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&fwd), 0);
	CHECK(fwd.len > 0);

	membuf_free(&rev); membuf_free(&fwd);
	CHECK(mb_block_maps_consistent(b));
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
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* A delta carries the allocation map, not just the bytes: a page mapped during
 * the epoch has to exist on the other side. */
static void test_delta_carries_allocation(void) {
	mb_block *b = sealed(0x20000);
	mb_range gone = { b->addr.start + 0x4000, 0x1000 };
	CHECK_EQ(mb_block_munmap(b, gone), 0);
	CHECK_EQ(mb_block_page_info(b, 4) & 0x3f, 0);   /* free */

	membuf anchor = { 0 };
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&anchor), 0);

	CHECK_EQ(mb_block_epoch_begin(b), 0);
	CHECK_EQ(mb_block_mmap_fixed(b, gone, MB_PROT_RW, false), 0);
	CHECK(((mb_block_page_info(b, 4) & 0x3f) != 0));

	membuf fwd = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&fwd), 0);

	/* rebuild the frame the way a seek does: back to the anchor, then forward */
	anchor.pos = 0;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&anchor), 0);
	CHECK_EQ(mb_block_page_info(b, 4) & 0x3f, 0);
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&fwd), 0);
	CHECK(((mb_block_page_info(b, 4) & 0x3f) != 0));

	membuf_free(&fwd); membuf_free(&anchor);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* A page can change hands inside an epoch - munmap'd and handed back - and the
 * delta owes the frame its BYTES, not just the shape of the map. Neither mmap
 * nor munmap goes through the fault handler, so this is the case where nothing
 * lifts the epoch's hold: it is covered today by free_pages taking the baseline
 * snapshot and zeroing as it goes, which is not obvious from either end. Pinned
 * here so that it stays true. */
static void test_delta_carries_remapped_contents(void) {
	const uintptr_t SIZE = 0x20000;
	mb_block *b = sealed(SIZE);
	for (uintptr_t i = 0; i < SIZE; i += 0x1000)
		memset((void *)(b->addr.start + i), (uint8_t)(i >> 12), 0x1000);

	membuf anchor = { 0 };
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&anchor), 0);

	CHECK_EQ(mb_block_epoch_begin(b), 0);
	uint8_t *before = snapshot(b, SIZE);

	mb_range page = { b->addr.start + 0x4000, 0x1000 };
	CHECK_EQ(mb_block_munmap(b, page), 0);
	CHECK_EQ(mb_block_mmap_fixed(b, page, MB_PROT_RW, false), 0);
	memset((void *)page.start, 0xEE, 0x1000);
	uint8_t *after = snapshot(b, SIZE);
	CHECK(memcmp(before, after, SIZE) != 0);

	membuf fwd = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&fwd), 0);

	anchor.pos = 0;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&anchor), 0);
	CHECK(memcmp((const void *)b->addr.start, before, SIZE) == 0);
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&fwd), 0);
	CHECK(memcmp((const void *)b->addr.start, after, SIZE) == 0);

	membuf_free(&fwd); membuf_free(&anchor);
	free(before); free(after);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* The other case: a page that was FREE when the epoch began and is handed to
 * the guest during it. Its contents are whatever the guest just put there, and
 * the delta owes them even though nothing faulted to say so. */
static void test_delta_carries_freshly_mapped_contents(void) {
	const uintptr_t SIZE = 0x20000;
	mb_block *b = sealed(SIZE);
	for (uintptr_t i = 0; i < SIZE; i += 0x1000)
		memset((void *)(b->addr.start + i), (uint8_t)(i >> 12), 0x1000);
	mb_range page = { b->addr.start + 0x6000, 0x1000 };
	CHECK_EQ(mb_block_munmap(b, page), 0);

	membuf anchor = { 0 };
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&anchor), 0);

	CHECK_EQ(mb_block_epoch_begin(b), 0);
	CHECK_EQ(mb_block_mmap_fixed(b, page, MB_PROT_RW, false), 0);
	memset((void *)page.start, 0x5A, 0x1000);
	uint8_t *after = snapshot(b, SIZE);

	membuf fwd = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&fwd), 0);

	/* back to free, then forward again: the bytes have to come with it */
	anchor.pos = 0;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&anchor), 0);
	CHECK_EQ(mb_block_page_info(b, 6) & 0x3f, 0);
	memset((void *)(b->addr.start + 0x7000), 0x11, 0x1000);   /* churn around it */
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&fwd), 0);
	CHECK(memcmp((const void *)page.start, (const uint8_t *)after + 0x6000, 0x1000) == 0);

	membuf_free(&fwd); membuf_free(&anchor);
	free(after);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* A page the guest GAVE BACK reads as zero, and a frame rebuilt from deltas has
 * to agree.
 *
 * munmap zeroes the page it takes away, because that is what the guest's next
 * mmap of it is entitled to find - musl hands fresh anonymous memory to malloc
 * on exactly that promise. Nothing about that zeroing goes through the fault
 * handler, so the epoch never hears about it: the delta records the page moving
 * to free and back, and not a byte of content. Replay the deltas and the page
 * comes back holding what it held BEFORE it was freed, which the guest then
 * hands out as fresh memory.
 *
 * This is the shape of a heap in ordinary use, and it is why a seek backwards
 * on a big core dies somewhere unrelated a hundred frames later. */
static void test_delta_zeroes_a_page_the_guest_gave_back(void) {
	const uintptr_t SIZE = 0x20000;
	mb_block *b = sealed(SIZE);
	for (uintptr_t i = 0; i < SIZE; i += 0x1000)
		memset((void *)(b->addr.start + i), 0xAB, 0x1000);

	membuf anchor = { 0 };
	CHECK_EQ(mb_block_save_state(b, membuf_write, (uintptr_t)&anchor), 0);

	mb_range page = { b->addr.start + 0x4000, 0x1000 };

	CHECK_EQ(mb_block_epoch_begin(b), 0);
	memset((void *)page.start, 0xCD, 0x1000);
	membuf d1 = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&d1), 0);

	/* given back and taken again, which is what a heap does all day */
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	CHECK_EQ(mb_block_munmap(b, page), 0);
	CHECK_EQ(mb_block_mmap_fixed(b, page, MB_PROT_RW, false), 0);
	membuf d2 = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&d2), 0);

	CHECK_EQ(((const volatile uint8_t *)page.start)[0], 0);  /* the machine says zero */
	uint8_t *live = snapshot(b, SIZE);

	/* now rebuild that frame the way a seek does: the anchor, then the deltas */
	anchor.pos = 0;
	CHECK_EQ(mb_block_load_state(b, membuf_read, (uintptr_t)&anchor), 0);
	d1.pos = 0;
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&d1), 0);
	d2.pos = 0;
	CHECK_EQ(mb_block_delta_apply(b, membuf_read, (uintptr_t)&d2), 0);
	CHECK_EQ(((const volatile uint8_t *)page.start)[0], 0);  /* and so must the rebuild */
	CHECK(memcmp((const void *)b->addr.start, live, SIZE) == 0);

	membuf_free(&anchor); membuf_free(&d1); membuf_free(&d2);
	free(live);
	CHECK(mb_block_maps_consistent(b));
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
	CHECK(mb_block_maps_consistent(b));
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
	CHECK(mb_block_maps_consistent(b));
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
	CHECK(mb_block_maps_consistent(b));
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
	CHECK(mb_block_maps_consistent(b));
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
	CHECK(mb_block_maps_consistent(b));
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
	CHECK(mb_block_maps_consistent(b));
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

/* The in-memory compose is the streaming one's answer, exactly. It exists only
 * because the caller that runs it every frame already holds both deltas
 * contiguously, so reading them into buffers to look at them was copying
 * megabytes for nothing - not because it does anything different. */
static void test_compose_in_memory_matches_streaming(void) {
	const uintptr_t SIZE = 0x40000;
	mb_block *b = sealed(SIZE);
	for (uintptr_t i = 0; i < SIZE; i += 0x1000) memset((void *)(b->addr.start + i), (uint8_t)(i >> 12), 0x1000);

	/* two deltas that overlap in part, and that move the allocation map too */
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	gp(b, 0x2000)[0] = 1;
	gp(b, 0x5000)[0] = 2;
	mb_range page = { b->addr.start + 0x9000, 0x1000 };
	CHECK_EQ(mb_block_munmap(b, page), 0);
	membuf d1 = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&d1), 0);

	CHECK_EQ(mb_block_epoch_begin(b), 0);
	gp(b, 0x5000)[0] = 3;                                  /* the same page again */
	gp(b, 0x7000)[0] = 4;                                  /* and one only this frame has */
	CHECK_EQ(mb_block_mmap_fixed(b, page, MB_PROT_RW, false), 0);
	membuf d2 = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&d2), 0);

	membuf streamed = { 0 }, inmem = { 0 };
	d1.pos = 0; d2.pos = 0;
	CHECK_EQ(mb_block_delta_compose(membuf_read, (uintptr_t)&d1, membuf_read, (uintptr_t)&d2,
		membuf_write, (uintptr_t)&streamed), 0);
	size_t used = 0;
	CHECK_EQ(mb_block_delta_compose_mem(d1.buf, d1.len, d2.buf, d2.len,
		membuf_write, (uintptr_t)&inmem, &used), 0);

	CHECK_EQ(inmem.len, streamed.len);
	CHECK(memcmp(inmem.buf, streamed.buf, streamed.len) == 0);
	CHECK_EQ(used, d2.len);   /* it consumed the whole of the later delta */

	/* rubbish is refused rather than read past the end of */
	membuf junk = { 0 };
	CHECK(mb_block_delta_compose_mem(d1.buf, d1.len, d1.buf, 4, membuf_write, (uintptr_t)&junk, NULL) != 0);
	CHECK(mb_block_delta_compose_mem(d1.buf, d1.len - 1, d2.buf, d2.len, membuf_write, (uintptr_t)&junk, NULL) != 0);

	membuf_free(&d1); membuf_free(&d2); membuf_free(&streamed); membuf_free(&inmem); membuf_free(&junk);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

static void run_all(void) {
	test_epoch_tracks_what_changed();
	test_forward_delta_reproduces();
	test_delta_applied_to_a_clean_page_keeps_the_baseline();
	test_delta_apply_leaves_its_pages_watched();
	test_hot_page_still_reports_every_change();
	test_hot_page_cools_and_is_exact();
	test_hot_page_survives_a_load();
	test_a_truncated_delta_leaves_pages_watched();
	test_a_truncated_delta_dirties_what_it_wrote();
	test_a_truncated_state_leaves_pages_watched();
	test_reverse_delta_is_refused();
	test_delta_chain_equals_the_run();
	test_delta_carries_allocation();
	test_delta_carries_remapped_contents();
	test_delta_carries_freshly_mapped_contents();
	test_delta_zeroes_a_page_the_guest_gave_back();
	test_delta_refusals();
	test_delta_needs_an_epoch();
	test_full_state_after_delta();
	test_compose_equals_applying_both();
	test_composing_a_chain_down_to_one();
	test_compose_carries_allocation();
	test_compose_refuses_a_foreign_delta();
	test_compose_in_memory_matches_streaming();
}

TEST_MAIN()
