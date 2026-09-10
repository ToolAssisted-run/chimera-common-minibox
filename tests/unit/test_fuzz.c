/* The page tracker against a model, under random use.
 *
 * Every other test here asks one question of one operation. This asks the only
 * question that matters of all of them together: after any sequence of writes,
 * maps, unmaps, protections and zeroings, does loading an anchor and applying
 * the deltas since it reproduce the machine byte for byte, frame by frame?
 *
 * The model is the mirror itself, copied after each frame, and the allocation
 * map as page_info reports it. A seek loads the nearest anchor, applies the
 * deltas - some of them composed in pairs first - and compares each landing
 * with the copy. The run then CONTINUES from where it landed, as a rerecord
 * does, so the tracker is exercised on a machine that has been put back as well
 * as on one that only ever went forward. Pages written every frame go hot;
 * pages written once do not; pages written with the bytes they already hold
 * must come out right whichever they are.
 *
 * Deterministic: a failure names its seed and step. */
#include "minibox_internal.h"
#include "test_util.h"
#include <stdlib.h>

#define NP 96
#define SIZE ((uintptr_t)NP << MB_PAGESHIFT)
#define MAXFRAMES 1400
#define HOT 6   /* pages written most frames */

static uint64_t g_rng;
static uint32_t rnd(void) { g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17; return (uint32_t)(g_rng >> 11); }
static uint32_t below(uint32_t n) { return rnd() % n; }

typedef struct {
	uint8_t *mem;            /* the whole block, as the mirror showed it */
	uint8_t status[NP];      /* page_info, status and invisibility */
	membuf delta;            /* what the frame recorded, if any */
	membuf anchor;           /* a whole state, every so often */
	bool has_anchor;
} frame_t;

static mb_block *g_b;
static uint8_t *mirror(size_t page) { return (uint8_t *)(g_b->mirror.start + (page << MB_PAGESHIFT)); }
static volatile uint8_t *guest(size_t page) { return (volatile uint8_t *)(g_b->addr.start + (page << MB_PAGESHIFT)); }
static uint8_t status_of(size_t page) { return mb_block_page_info(g_b, page) & 0x3f; }
static bool writable(size_t page) { uint8_t s = status_of(page); return s == MB_ST_RW || s == MB_ST_RWX; }

static void snapshot(frame_t *f) {
	if (!f->mem) f->mem = malloc(SIZE);
	memcpy(f->mem, mirror(0), SIZE);
	for (size_t i = 0; i < NP; i++) f->status[i] = status_of(i);
}

static int g_seed, g_step;

static bool bit_of(const uint64_t *w, size_t i) { return (w[i >> 6] >> (i & 63)) & 1u; }

/* mb_block_maps_consistent, but saying which page and why */
static bool consistent(const char *where) {
	const mb_block *b = g_b;
	size_t hot = 0;
	for (size_t i = 0; i < b->npages; i++) {
		const mb_page *p = &b->pages[i];
		const char *why = NULL;
		if (b->status_map[i] != p->status || b->dirty_map[i] != (uint8_t)p->dirty) why = "packed map";
		else if (p->hot != bit_of(b->hot_bits, i)) why = "hot bit";
		else if (p->hot && !p->dirty) why = "hot but clean";
		else if (p->hot && p->shadow == NULL) why = "hot without shadow";
		else if (p->hot && bit_of(b->unheld_bits, i)) why = "hot and unheld";
		else if (!p->hot && p->shadow != NULL && p->status != MB_ST_RWSTACK) why = "shadow while cold";
		if (why) {
			fprintf(stderr, "  seed %d step %d (%s): page %zu: %s (status %02x dirty %d hot %d heat %d hold %d edirty %d)\n",
				g_seed, g_step, where, i, why, p->status, p->dirty, p->hot, p->heat, p->epoch_hold, p->epoch_dirty);
			return false;
		}
		hot += p->hot;
	}
	if (hot != b->nhot) { fprintf(stderr, "  seed %d step %d (%s): %zu hot pages, nhot says %zu\n", g_seed, g_step, where, hot, b->nhot); return false; }
	return true;
}

static bool matches(const frame_t *f, const char *what, int frame) {
	bool ok = true;
	for (size_t i = 0; i < NP && ok; i++) {
		if (memcmp(mirror(i), f->mem + (i << MB_PAGESHIFT), MB_PAGESIZE) != 0) {
			fprintf(stderr, "  seed %d step %d: %s frame %d page %zu content differs\n", g_seed, g_step, what, frame, i);
			ok = false;
		}
		if (status_of(i) != f->status[i]) {
			fprintf(stderr, "  seed %d step %d: %s frame %d page %zu status %02x, model %02x\n",
				g_seed, g_step, what, frame, i, status_of(i), f->status[i]);
			ok = false;
		}
	}
	return ok;
}

/* a run of `n` pages in a state the caller wants, or -1 */
static long find_run(bool want_mapped, size_t n) {
	size_t start = below(NP);
	for (size_t tries = 0; tries < NP; tries++) {
		size_t s = (start + tries) % NP;
		if (s + n > NP) continue;
		bool ok = true;
		for (size_t k = 0; k < n; k++) {
			bool mapped = status_of(s + k) != MB_ST_FREE;
			if (mapped != want_mapped) { ok = false; break; }
		}
		if (ok) return (long)s;
	}
	return -1;
}

static void one_write(void) {
	/* a hot page most of the time, any writable page the rest */
	size_t page;
	for (int tries = 0; tries < 32; tries++) {
		page = below(4) != 0 ? (size_t)(8 + below(HOT)) : (size_t)below(NP);
		if (writable(page)) break;
		page = NP;
	}
	if (page == NP) return;
	size_t off = below(MB_PAGESIZE);
	uint8_t v = (uint8_t)rnd();
	if (below(4) == 0) v = guest(page)[off];   /* the bytes it already holds */
	guest(page)[off] = v;
}

static void one_op(void) {
	switch (below(20)) {
	case 0: {   /* map a free run */
		size_t n = 1 + below(3);
		long s = find_run(false, n);
		if (s < 0) return;
		mb_range r = { g_b->addr.start + ((uintptr_t)s << MB_PAGESHIFT), n << MB_PAGESHIFT };
		CHECK_EQ(mb_block_mmap_fixed(g_b, r, MB_PROT_RW, true), 0);
		return;
	}
	case 1: {   /* give a mapped run back */
		size_t n = 1 + below(2);
		long s = find_run(true, n);
		if (s < 0 || s < 8 + HOT) return;   /* keep the hot pages and the first ones mapped */
		mb_range r = { g_b->addr.start + ((uintptr_t)s << MB_PAGESHIFT), n << MB_PAGESHIFT };
		CHECK_EQ(mb_block_munmap(g_b, r), 0);
		return;
	}
	case 2: {   /* read-only, and back */
		long s = find_run(true, 1);
		if (s < 0 || s < 8 + HOT) return;
		mb_range r = { g_b->addr.start + ((uintptr_t)s << MB_PAGESHIFT), MB_PAGESIZE };
		CHECK_EQ(mb_block_mprotect(g_b, r, status_of((size_t)s) == MB_ST_R ? MB_PROT_RW : MB_PROT_R), 0);
		return;
	}
	case 3: {   /* zeroed, kept */
		long s = find_run(true, 1);
		if (s < 0) return;
		mb_range r = { g_b->addr.start + ((uintptr_t)s << MB_PAGESHIFT), MB_PAGESIZE };
		CHECK_EQ(mb_block_madvise_dontneed(g_b, r), 0);
		return;
	}
	default:
		one_write();
		return;
	}
}

static void run_seed(int seed, int steps) {
	g_seed = seed;
	g_rng = 0x9E3779B97F4A7C15ull * (uint64_t)(seed + 1);
	mb_range a = { 0x36f00000000ull, SIZE };
	g_b = mb_block_new(a);
	mb_block_activate(g_b);
	mb_range r = { g_b->addr.start, (uintptr_t)(NP / 2) << MB_PAGESHIFT };
	CHECK_EQ(mb_block_mmap_fixed(g_b, r, MB_PROT_RW, true), 0);
	for (size_t i = 0; i < NP / 2; i++) guest(i)[7] = (uint8_t)(i * 3);
	CHECK_EQ(mb_block_seal(g_b), 0);

	static frame_t frames[MAXFRAMES];
	for (int i = 0; i < MAXFRAMES; i++) { membuf_free(&frames[i].delta); membuf_free(&frames[i].anchor); frames[i].has_anchor = false; }
	int n = 0;   /* frames recorded: frame 0 is the sealed machine */
	frames[0].has_anchor = true;
	CHECK_EQ(mb_block_save_state(g_b, membuf_write, (uintptr_t)&frames[0].anchor), 0);
	snapshot(&frames[0]);
	n = 1;

	for (g_step = 0; g_step < steps && n + 1 < MAXFRAMES; g_step++) {
		/* a frame */
		CHECK_EQ(mb_block_epoch_begin(g_b), 0);
		int ops = 1 + (int)below(12);
		for (int k = 0; k < ops; k++) one_op();
		frame_t *f = &frames[n];
		membuf_free(&f->delta);
		CHECK_EQ(mb_block_delta_save(g_b, true, membuf_write, (uintptr_t)&f->delta), 0);
		membuf_free(&f->anchor);
		f->has_anchor = below(9) == 0;
		if (f->has_anchor) CHECK_EQ(mb_block_save_state(g_b, membuf_write, (uintptr_t)&f->anchor), 0);
		snapshot(f);
		n++;
		CHECK(consistent("after frame"));
		if (mb_test_fails) return;

		/* a seek, now and then: back to a frame, then forward through the
		 * deltas, and on from there */
		if (below(14) != 0) continue;
		int target = (int)below((uint32_t)n);
		int anchor = target;
		while (!frames[anchor].has_anchor) anchor--;
		frames[anchor].anchor.pos = 0;
		CHECK_EQ(mb_block_load_state(g_b, membuf_read, (uintptr_t)&frames[anchor].anchor), 0);
		if (!matches(&frames[anchor], "anchor", anchor)) return;
		for (int k = anchor + 1; k <= target; k++) {
			if (k + 1 <= target && below(3) == 0) {
				/* two at once, composed */
				membuf both = { 0 };
				size_t used = 0;
				CHECK_EQ(mb_block_delta_compose_mem(frames[k].delta.buf, frames[k].delta.len,
					frames[k + 1].delta.buf, frames[k + 1].delta.len, membuf_write, (uintptr_t)&both, &used), 0);
				CHECK_EQ(used, frames[k + 1].delta.len);
				both.pos = 0;
				CHECK_EQ(mb_block_delta_apply(g_b, membuf_read, (uintptr_t)&both), 0);
				membuf_free(&both);
				k++;
			} else {
				frames[k].delta.pos = 0;
				CHECK_EQ(mb_block_delta_apply(g_b, membuf_read, (uintptr_t)&frames[k].delta), 0);
			}
			if (!matches(&frames[k], "replay", k)) return;
		}
		CHECK(consistent("after seek"));
		if (mb_test_fails) return;
		/* the frames after the target are a timeline that no longer happens */
		n = target + 1;
	}

	/* the last word: every anchor still loads to what it was */
	for (int k = 0; k < n; k++) {
		if (!frames[k].has_anchor) continue;
		frames[k].anchor.pos = 0;
		CHECK_EQ(mb_block_load_state(g_b, membuf_read, (uintptr_t)&frames[k].anchor), 0);
		if (!matches(&frames[k], "final", k)) return;
	}
	for (int i = 0; i < MAXFRAMES; i++) { membuf_free(&frames[i].delta); membuf_free(&frames[i].anchor); free(frames[i].mem); frames[i].mem = NULL; }
	mb_block_free(g_b);
	g_b = NULL;
}

static void test_random_runs(void) {
	const char *env = getenv("MB_FUZZ_STEPS");
	int steps = env ? atoi(env) : 700;
	for (int seed = 0; seed < 6; seed++) {
		run_seed(seed, steps);
		if (mb_test_fails) return;
	}
}

static void run_all(void) {
	RUN(test_random_runs);
}

TEST_MAIN()
