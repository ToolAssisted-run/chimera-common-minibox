/* The memory block: guest address space with page-granular dirty tracking
 * against a sealed baseline, and whole-machine savestates. Faithful C port of
 * BizHawk waterboxhost src/memory_block/mod.rs (Linux subset; single-slice, no lazy-evict).
 *
 * Model: the block's backing store is a memfd mapped twice - at the fixed guest
 * address `addr` (protection-managed for dirty tracking) and at an OS-chosen
 * always-RW `mirror`. All host-side reads/writes go through the mirror so they
 * never trip dirty detection. mirror_of(guest_addr) = guest_addr - addr.start +
 * mirror.start.
 */
#include "minibox_internal.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Phase 1 is Linux single-slice: at most one block occupies its 4GiB region at
 * a time and stays resident. (The Rust reference supports many blocks sharing a
 * slice via a per-slice mutex + lazy swap; not needed until multi-core hosting.) */

static uintptr_t mirror_addr(const mb_block *b, uintptr_t guest) {
	return guest - b->addr.start + b->mirror.start;
}

static mb_prot status_prot(uint8_t s) {
	switch (s) {
		case MB_ST_NONE: return MB_PROT_NONE;
		case MB_ST_R: return MB_PROT_R;
		case MB_ST_RW: return MB_PROT_RW;
		case MB_ST_RX: return MB_PROT_RX;
		case MB_ST_RWX: return MB_PROT_RWX;
		case MB_ST_RWSTACK: return MB_PROT_RWSTACK;
		default: return MB_PROT_NONE;
	}
}

/* prot -> status byte (inverse of status_prot) */
static uint8_t prot_status(mb_prot prot) {
	switch (prot) {
		case MB_PROT_NONE: return MB_ST_NONE;
		case MB_PROT_R: return MB_ST_R;
		case MB_PROT_RW: return MB_ST_RW;
		case MB_PROT_RX: return MB_ST_RX;
		case MB_PROT_RWX: return MB_ST_RWX;
		case MB_PROT_RWSTACK: return MB_ST_RWSTACK;
	}
	return MB_ST_NONE;
}

/* Effective host protection: clean writable pages map read-only so the first
 * write faults (dirty tracking). RWStack is R-until-written on Linux; on Windows
 * it is plain RW and never clean at all.
 *
 * WHY A STACK IS DIFFERENT ON WINDOWS, AND WHY ONLY A STACK.
 *
 * A read-only page whose write faults is fine right up until the page is the
 * one the stack pointer is in. Windows delivers an exception by pushing a
 * context record onto the faulting thread's own stack, so a write fault on the
 * stack cannot be reported: the kernel's own write fails too and the process
 * dies with no handler having run, no diagnostic, and an access violation as
 * its exit code.
 *
 * A guard page has none of that problem: the kernel clears the guard bit BEFORE
 * it raises the exception, so the page is writable by the time the context
 * record goes onto it. That is why a stack is one.
 *
 * It is TEMPTING to protect every clean page that way and never think about
 * where the guest keeps its stack. It does not work, and the way it fails is
 * the worst kind: a guard bit can also be cleared with no exception delivered
 * at all, and then every later write to that page is invisible and the page is
 * still recorded clean. Measured on Windows with ares: a few hundred pages an
 * epoch lost their guard with no handler ever running for them, and seeking
 * through the history came back with a machine the plain run never had. A
 * read-only page cannot fail that way - nothing but this file makes it
 * writable - so ordinary memory is read-only here exactly as it is on Linux.
 *
 * The price is that a guest MUST SAY WHERE ITS STACKS ARE, with MAP_STACK, and
 * a guest that runs on memory it merely allocated dies on its first frame. ares
 * gave every emulated component a coroutine stack out of malloc and did exactly
 * that; it asks for them with MAP_STACK now. */
mb_prot mb_page_native_prot(const mb_page *p) {
	if (p->status == MB_ST_FREE) return MB_PROT_NONE;
	/* A hot page is never held: it is written every frame, so the fault a
	 * hold buys would come every frame too. It is compared instead (page_heat). */
	if (p->hot) return status_prot(p->status);
	/* An open epoch holds a page read-only until it is written, exactly as the
	 * baseline tracking does - so one page can be held for either reason, and
	 * the fault that lifts the hold serves both. */
	bool clean = !p->dirty || p->epoch_hold;
	if (p->status == MB_ST_RW && clean) return MB_PROT_R;
	if (p->status == MB_ST_RWX && clean) return MB_PROT_RX;
#ifndef _WIN32
	if (p->status == MB_ST_RWSTACK) return clean ? MB_PROT_R : MB_PROT_RW;
#endif
	return status_prot(p->status);  /* Windows: a stack is plain RW, never clean */
}

/* Snapshot storage, allocated WITHOUT malloc.
 *
 * A page's baseline copy is taken inside the SIGSEGV handler, and malloc is not
 * async-signal-safe: the fault can land in the middle of the host's own
 * allocation - a graphics driver allocates constantly - and the handler then
 * re-enters the allocator on a lock it already holds. It survives while few
 * pages are taken, and stops surviving the moment a core is sealed, because
 * sealing marks every dirty page clean again and thousands of faults arrive at
 * once. (Nine thousand snapshots in, this died with no diagnosis possible: a
 * fault inside the handler is delivered with SIGSEGV blocked, so the process is
 * killed outright and nothing gets to say why.)
 *
 * So the snapshots come from pages this file maps itself, in chunks, and are
 * handed out through a small free list. mmap and munmap are plain syscalls and
 * safe to call from a handler; the spin lock covers the driver threads that can
 * fault at the same time as the guest. */
#define SNAP_CHUNK_PAGES 512
static uint8_t **g_snap_free;      /* stack of free page-sized slots */
static size_t g_snap_free_count, g_snap_free_cap;
static volatile int g_snap_lock;

static void snap_lock(void) { while (__atomic_test_and_set(&g_snap_lock, __ATOMIC_ACQUIRE)) { } }
static void snap_unlock(void) { __atomic_clear(&g_snap_lock, __ATOMIC_RELEASE); }

static uint8_t *snap_alloc(void) {
	snap_lock();
	if (g_snap_free_count == 0) {
		mb_range in = { 0, SNAP_CHUNK_PAGES * MB_PAGESIZE }, got;
		if (mb_pal_map_anon(in, MB_PROT_RW, &got) != 0) { snap_unlock(); return NULL; }
		if (g_snap_free_cap < g_snap_free_count + SNAP_CHUNK_PAGES) {
			/* the index itself may grow, and here we are outside the handler's
			 * hot path often enough that a mapping is the honest way to do it */
			size_t want = (g_snap_free_cap ? g_snap_free_cap * 2 : 1024);
			while (want < g_snap_free_count + SNAP_CHUNK_PAGES) want *= 2;
			mb_range iin = { 0, want * sizeof(uint8_t *) }, igot;
			if (mb_pal_map_anon(iin, MB_PROT_RW, &igot) != 0) { snap_unlock(); return NULL; }
			uint8_t **ni = (uint8_t **)igot.start;
			for (size_t i = 0; i < g_snap_free_count; i++) ni[i] = g_snap_free[i];
			if (g_snap_free) { mb_range old = { (uintptr_t)g_snap_free, g_snap_free_cap * sizeof(uint8_t *) }; mb_pal_unmap_anon(old); }
			g_snap_free = ni; g_snap_free_cap = want;
		}
		for (size_t i = 0; i < SNAP_CHUNK_PAGES; i++)
			g_snap_free[g_snap_free_count++] = (uint8_t *)(got.start + i * MB_PAGESIZE);
	}
	uint8_t *r = g_snap_free[--g_snap_free_count];
	snap_unlock();
	return r;
}

static void snap_release(uint8_t *p) {
	if (!p) return;
	snap_lock();
	if (g_snap_free_count < g_snap_free_cap) g_snap_free[g_snap_free_count++] = p;
	snap_unlock();
}

void mb_page_maybe_snapshot(mb_page *p, uintptr_t maddr) {
	/* a page nothing has backed yet holds zeros and cannot be read */
	if (p->uncommitted) {
		if (p->snap_kind == MB_SNAP_NONE) p->snap_kind = MB_SNAP_ZERO;
		return;
	}
	if (p->snap_kind == MB_SNAP_NONE) {
		p->snap_data = snap_alloc();
		if (!p->snap_data) return;   /* out of room: leave it clean rather than crash */
		memcpy(p->snap_data, (const void *)maddr, MB_PAGESIZE);
		p->snap_kind = MB_SNAP_DATA;
	}
}

static bool epoch_tracks(const mb_page *p);

/* ---- page-index bitmaps -------------------------------------------------
 *
 * Every per-frame path used to walk the page array from end to end. On a two
 * gigabyte arena that is half a million forty-byte structs - twenty-one
 * megabytes of memory traffic - several times per captured frame, to describe
 * a few hundred pages of change. Measured, it cost around nine milliseconds a
 * frame, and it cost the same whether the frame wrote sixteen pages or a
 * thousand: the work was proportional to how big the machine COULD be.
 *
 * So the sets a frame cares about are bitmaps instead: one bit a page, sixty
 * four kilobytes for that same arena, scanned a word at a time and skipping
 * the empty ones. Ascending, which the delta format needs - both its lists are
 * in page order so that composing two deltas is a merge of sorted runs. */
#if defined(_MSC_VER)
#include <intrin.h>
static inline int bits_first(uint64_t x) { unsigned long i; _BitScanForward64(&i, x); return (int)i; }
#else
static inline int bits_first(uint64_t x) { return __builtin_ctzll(x); }
#endif

static inline void bits_set(uint64_t *w, size_t i) { w[i >> 6] |= 1ull << (i & 63); }
static inline void bits_clr(uint64_t *w, size_t i) { w[i >> 6] &= ~(1ull << (i & 63)); }
static inline bool bits_get(const uint64_t *w, size_t i) { return (w[i >> 6] >> (i & 63)) & 1u; }
static inline void bits_none(mb_block *b, uint64_t *w) { memset(w, 0, b->nwords * sizeof(uint64_t)); }

/* A page is "unheld" when it is mapped writable right now, which is exactly
 * the set an epoch has to protect again. Kept where protections are applied,
 * so the bitmap cannot drift from what the OS was actually told. */
static void note_prot(mb_block *b, size_t i, mb_prot prot) {
	bool writable = prot == MB_PROT_RW || prot == MB_PROT_RWX || prot == MB_PROT_RWSTACK;
	/* a hot page is writable and is never to be held, so it is not "unheld" */
	if (writable && !b->pages[i].hot) bits_set(b->unheld_bits, i);
	else bits_clr(b->unheld_bits, i);
}

void mb_block_note_unheld(mb_block *b, size_t pi) { bits_set(b->unheld_bits, pi); }

/* Membership of the stack set, which only Windows uses (mb_page_native_prot):
 * a page that stops being a stack gives its shadow back. */
static void page_cool(mb_block *b, size_t i);

static void note_status(mb_block *b, size_t i, uint8_t status) {
	/* an allocation that moves is a different page, whatever it held */
	if (b->pages[i].hot && b->pages[i].status != status) page_cool(b, i);
	b->pages[i].status = status;
	b->status_map[i] = status;
#ifdef _WIN32
	if (status == MB_ST_RWSTACK) { bits_set(b->stack_bits, i); return; }
	if (bits_get(b->stack_bits, i)) {
		bits_clr(b->stack_bits, i);
		snap_release(b->pages[i].shadow);
		b->pages[i].shadow = NULL;
	}
#endif
}

static inline void set_dirty(mb_block *b, size_t i, bool dirty) {
	b->pages[i].dirty = dirty;
	b->dirty_map[i] = dirty;
}

void mb_block_note_dirty(mb_block *b, size_t pi, bool dirty) { set_dirty(b, pi, dirty); }

bool mb_block_maps_consistent(const mb_block *b) {
	size_t hot = 0;
	for (size_t i = 0; i < b->npages; i++) {
		const mb_page *p = &b->pages[i];
		if (b->status_map[i] != p->status || b->dirty_map[i] != (uint8_t)p->dirty) return false;
		if (p->hot != bits_get(b->hot_bits, i)) return false;
		if (p->hot && (!p->dirty || p->shadow == NULL || bits_get(b->unheld_bits, i))) return false;
		if (!p->hot && p->shadow != NULL && p->status != MB_ST_RWSTACK) return false;
		hot += p->hot;
	}
	return hot == b->nhot;
}

/* ---- hot pages -------------------------------------------------------------
 *
 * Every write a delta reports costs a fault: the page is read-only until the
 * guest touches it, the handler marks it and makes it writable, and the next
 * epoch protects it again so that the same can happen next frame. That is the
 * right price for a page the machine writes now and then. It is the wrong
 * price for the pages it writes EVERY frame - a framebuffer, the audio ring,
 * the CPU's own registers - which pay a fault and a re-protection each, per
 * frame, forever, to report what was already known. Measured on ares' N64: a
 * frame writes some three hundred pages, most of them the same three hundred
 * as last frame, and the faults were two thirds of what capturing it cost.
 *
 * So a page written a few frames in a row goes hot: it stays writable, and
 * what it did is found by comparing it with a copy taken when the epoch
 * opened. Copying and comparing four kilobytes is a fraction of a microsecond;
 * a fault is several. A hot page that stops changing cools after a few frames
 * and is held again like any other. The comparison is also exact where the
 * fault is not: a page written with the bytes it already held is left out of
 * the delta, which is memory the fault could never save.
 *
 * The invariant is that a hot page's shadow is the page as the epoch opened.
 * Opening an epoch copies every hot page - nothing here can know whether the
 * guest ran since the last delta was saved - and the two operations that
 * rewrite pages from outside the guest, a state loaded and a delta applied,
 * refresh the copy or cool the page as they go. A page whose allocation
 * changes cools (note_status); so does one a state load makes clean, because
 * a clean page is held for the baseline's sake. Windows stacks are never hot:
 * they have a shadow of their own already, kept against the sealed baseline. */
#define HOT_AFTER   3       /* frames written in a row before a page goes hot */
#define COLD_AFTER  8       /* frames unchanged in a row before it cools */
#define HOT_MOST    32768   /* pages - 128MB of shadows - a cap, not a target */

static void page_cool(mb_block *b, size_t i) {
	mb_page *p = &b->pages[i];
	if (!p->hot) return;
	p->hot = false;
	p->heat = 0;
	snap_release(p->shadow);
	p->shadow = NULL;
	bits_clr(b->hot_bits, i);
	b->nhot--;
	/* it is mapped writable - a hot page always is - so the next epoch owes it
	 * a hold, exactly as if a fault had just let a write through */
	bits_set(b->unheld_bits, i);
}

/* A page that has earned it, if it may: tracked, dirty (a written page always
 * is), mapped writable right now (unheld: a hot page stays as it is mapped),
 * and not a stack. */
static void page_heat(mb_block *b, size_t i) {
	mb_page *p = &b->pages[i];
	if (p->hot || p->invisible || p->uncommitted || !p->dirty) return;
	if (p->status != MB_ST_RW && p->status != MB_ST_RWX) return;
	if (!bits_get(b->unheld_bits, i) || b->nhot >= HOT_MOST) return;
	uint8_t *shadow = snap_alloc();
	if (!shadow) return;
	memcpy(shadow, (const void *)mirror_addr(b, b->addr.start + (i << MB_PAGESHIFT)), MB_PAGESIZE);
	p->shadow = shadow;
	p->hot = true;
	p->heat = 0;
	bits_set(b->hot_bits, i);
	bits_clr(b->unheld_bits, i);
	b->nhot++;
}

/* What the hot pages did this epoch, by looking. */
static void get_hot_epoch(mb_block *b) {
	for (size_t w = 0; w < b->nwords; w++) {
		uint64_t m = b->hot_bits[w];
		while (m) {
			size_t i = (w << 6) + (size_t)bits_first(m);
			m &= m - 1;
			mb_page *p = &b->pages[i];
			const void *live = (const void *)mirror_addr(b, b->addr.start + (i << MB_PAGESHIFT));
			if (memcmp(live, p->shadow, MB_PAGESIZE) == 0) {
				if (++p->heat >= COLD_AFTER) page_cool(b, i);
				continue;
			}
			p->heat = 0;
			if (p->epoch_dirty) continue;
			p->epoch_dirty = true;
			bits_set(b->epoch_bits, i);
			b->epoch_ndirty++;
		}
	}
}

/* Pages written this frame that were written last frame too are on their way
 * to hot. Runs after the delta is out, so the shadow a promotion takes is the
 * page as the delta left it. */
static void heat_written_pages(mb_block *b) {
	for (size_t w = 0; w < b->nwords; w++) {
		uint64_t m = b->epoch_bits[w];
		while (m) {
			size_t i = (w << 6) + (size_t)bits_first(m);
			m &= m - 1;
			mb_page *p = &b->pages[i];
			if (p->hot) continue;
			if (p->seen == (uint16_t)(b->epoch_no - 1)) { if (p->heat < 255) p->heat++; }
			else p->heat = 1;
			p->seen = b->epoch_no;
			if (p->heat >= HOT_AFTER) page_heat(b, i);
		}
	}
}

/* The epoch's half of the same fault: this page has been written, so the frame
 * owes it. Nothing is copied here - a delta is read off the live pages when it
 * is saved - so this runs in the handler and touches two words. */
void mb_block_epoch_capture(mb_block *b, size_t pi, uintptr_t maddr) {
	(void)maddr;
	mb_page *p = &b->pages[pi];
	/* Whether or not an epoch wants this page, the hold is over: the write that
	 * brought us here is about to be let through. */
	p->epoch_hold = false;
	/* An epoch tracks a page whether or not it was HELD. A page that was
	 * already read-only - clean against the baseline - needed no hold and got
	 * none, and it still belongs in the delta the moment it is written. */
	if (!b->epoch_active || !epoch_tracks(p) || p->epoch_dirty) return;
	p->epoch_dirty = true;
	bits_set(b->epoch_bits, pi);
	b->epoch_ndirty++;
}

/* ---- construction ---- */

mb_block *mb_block_new(mb_range addr) {
	if (addr.start != mb_align_down(addr.start) || addr.size != mb_align_down(addr.size)) {
		fprintf(stderr, "miniBox: addresses and sizes must be aligned\n");
		return NULL;
	}
	if (addr.start & 0xffffffffu) {
		fprintf(stderr, "miniBox: MemoryBlock must start on a 4G boundary\n");
		return NULL;
	}
	mb_block *b = (mb_block *)calloc(1, sizeof(mb_block));
	if (!b) return NULL;
	b->npages = addr.size >> MB_PAGESHIFT;
	b->pages = (mb_page *)calloc(b->npages, sizeof(mb_page));
	b->nwords = (b->npages + 63) / 64;
	b->epoch_bits = (uint64_t *)calloc(b->nwords, sizeof(uint64_t));
	b->stat_bits = (uint64_t *)calloc(b->nwords, sizeof(uint64_t));
	b->unheld_bits = (uint64_t *)calloc(b->nwords, sizeof(uint64_t));
	b->stack_bits = (uint64_t *)calloc(b->nwords, sizeof(uint64_t));
	b->hot_bits = (uint64_t *)calloc(b->nwords, sizeof(uint64_t));
	b->epoch_status = (uint8_t *)calloc(b->npages ? b->npages : 1, 1);
	b->status_map = (uint8_t *)calloc(b->npages ? b->npages : 1, 1);
	b->dirty_map = (uint8_t *)calloc(b->npages ? b->npages : 1, 1);
	if (!b->pages || !b->epoch_bits || !b->stat_bits || !b->unheld_bits || !b->stack_bits || !b->hot_bits
		|| !b->epoch_status || !b->status_map || !b->dirty_map) {
		free(b->pages); free(b->epoch_bits); free(b->stat_bits);
		free(b->unheld_bits); free(b->stack_bits); free(b->hot_bits); free(b->epoch_status);
		free(b->status_map); free(b->dirty_map); free(b);
		return NULL;
	}
	b->addr = addr;
	for (size_t i = 0; i < b->npages; i++) {
		b->pages[i].status = MB_ST_FREE;
		b->pages[i].snap_kind = MB_SNAP_ZERO; /* Free pages read as zero */
	}
	if (mb_pal_open_handle(addr.size, &b->handle) != 0) { free(b->pages); free(b); return NULL; }
	mb_range m_in = { 0, addr.size };
	if (mb_pal_map_handle(b->handle, m_in, &b->mirror) != 0) {
		mb_pal_close_handle(b->handle); free(b->pages); free(b); return NULL;
	}
	if (b->handle.lazy)
		for (size_t i = 0; i < b->npages; i++) b->pages[i].uncommitted = true;
	else
		mb_pal_protect(b->mirror, MB_PROT_RW);
	return b;
}

/* Lazy blocks: back every still-unbacked page of the run in both views
 * before anything touches it (the guest through its protection, the host
 * through the mirror). Committed pages stay committed for the block's life;
 * the guest view gets no access here, refresh_range sets its protection. */
static void ensure_committed(mb_block *b, size_t pstart, size_t pcount) {
	if (!b->handle.lazy) return;
	size_t i = pstart;
	while (i < pstart + pcount) {
		if (!b->pages[i].uncommitted) { i++; continue; }
		size_t j = i + 1;
		while (j < pstart + pcount && b->pages[j].uncommitted) j++;
		mb_range m = { mirror_addr(b, b->addr.start + (i << MB_PAGESHIFT)), (j - i) << MB_PAGESHIFT };
		mb_pal_commit(m, MB_PROT_RW);
		if (b->swapped_in) {
			mb_range g = { b->addr.start + (i << MB_PAGESHIFT), (j - i) << MB_PAGESHIFT };
			mb_pal_commit(g, MB_PROT_NONE);
		}
		for (size_t k = i; k < j; k++) b->pages[k].uncommitted = false;
		i = j;
	}
}

static void refresh_all(mb_block *b);

void mb_block_activate(mb_block *b) {
	if (b->active) return;
	if (!b->swapped_in) {
		mb_range in = b->addr, out;
		if (mb_pal_map_handle(b->handle, in, &out) != 0) {
			fprintf(stderr, "miniBox: FATAL failed to map block at %llx (slice busy?)\n",
			        (unsigned long long)b->addr.start);
			abort();
		}
		mb_tripguard_register(b);
		b->swapped_in = true;
		/* pages the host already backed through the mirror (copy_from_external
		 * before activation) need their guest-view backing now */
		if (b->handle.lazy) {
			size_t i = 0;
			while (i < b->npages) {
				if (b->pages[i].uncommitted) { i++; continue; }
				size_t j = i + 1;
				while (j < b->npages && !b->pages[j].uncommitted) j++;
				mb_range g = { b->addr.start + (i << MB_PAGESHIFT), (j - i) << MB_PAGESHIFT };
				mb_pal_commit(g, MB_PROT_NONE);
				i = j;
			}
		}
		refresh_all(b);
	}
	b->active = true;
}

void mb_block_deactivate(mb_block *b) {
	if (!b->active) return;
	/* Phase 1: keep resident (Linux, single block). Just drop the active flag;
	 * the mapping stays so mirror math and pointers remain valid. */
	b->active = false;
}

void mb_block_free(mb_block *b) {
	if (!b) return;
	if (b->swapped_in) {
		mb_tripguard_unregister(b);
		mb_pal_unmap_handle(b->addr);
		b->swapped_in = false;
	}
	mb_pal_unmap_anon(b->mirror);
	mb_pal_close_handle(b->handle);
	for (size_t i = 0; i < b->npages; i++) {
		snap_release(b->pages[i].snap_data);
		snap_release(b->pages[i].shadow);
	}
	free(b->epoch_status);
	free(b->epoch_bits);
	free(b->stat_bits);
	free(b->unheld_bits);
	free(b->stack_bits);
	free(b->hot_bits);
	free(b->status_map);
	free(b->dirty_map);
	free(b->pages);
	free(b);
}

/* ---- protection refresh (coalesced) ---- */

static void refresh_range(mb_block *b, size_t pstart, size_t pcount) {
	if (!b->swapped_in) return;
	size_t i = pstart;
	while (i < pstart + pcount) {
		mb_prot prot = mb_page_native_prot(&b->pages[i]);
		size_t j = i + 1;
		while (j < pstart + pcount && mb_page_native_prot(&b->pages[j]) == prot) j++;
		mb_range r = { b->addr.start + (i << MB_PAGESHIFT), (j - i) << MB_PAGESHIFT };
		if (prot != MB_PROT_NONE) ensure_committed(b, i, j - i);
		mb_pal_protect(r, prot);
		for (size_t k = i; k < j; k++) note_prot(b, k, prot);
		i = j;
	}
}

static void refresh_all(mb_block *b) { refresh_range(b, 0, b->npages); }

/* Pages whose protection an operation changed, refreshed as runs.
 *
 * A delta's lists come in ascending page order, so consecutive changed pages
 * make one run and the first page that is skipped - or whose protection did
 * not change - closes it. A page whose protection did NOT change is not
 * refreshed at all: the OS already has what mb_page_native_prot says, which
 * is the same invariant load_state relies on. */
typedef struct { size_t start, last; bool open; } prot_run;

static void run_note(mb_block *b, prot_run *run, size_t i) {
	if (run->open && i == run->last + 1) { run->last = i; return; }
	if (run->open) refresh_range(b, run->start, run->last - run->start + 1);
	run->start = run->last = i;
	run->open = true;
}

static void run_close(mb_block *b, prot_run *run) {
	if (run->open) refresh_range(b, run->start, run->last - run->start + 1);
	run->open = false;
}

/* ---- range validation ---- */

/* Returns page index start, or SIZE_MAX on EINVAL. */
static size_t validate(mb_block *b, mb_range addr, size_t *pcount) {
	if (addr.start < b->addr.start || mb_range_end(addr) > mb_range_end(b->addr)
		|| addr.size == 0
		|| addr.start != mb_align_down(addr.start) || addr.size != mb_align_down(addr.size))
		return (size_t)-1;
	*pcount = addr.size >> MB_PAGESHIFT;
	return (addr.start - b->addr.start) >> MB_PAGESHIFT;
}

/* A page whose ALLOCATION changes inside an epoch has to enter that epoch's
 * delta exactly as a written one does.
 *
 * A write is not the only way a page stops holding what the epoch began with.
 * mmap hands the guest a page that was free, munmap takes one away and ZEROES
 * it on the way out, mprotect turns a read-only page writable - and none of
 * those goes through the fault handler, so none of them lifted the epoch's hold
 * or copied a pre-image. The status list already said what the allocation map
 * DID; without this the delta carries the new shape of the machine and not the
 * bytes that came with it.
 *
 * The one that bites is munmap. A guest's heap gives pages back and takes them
 * again all day, and musl hands fresh anonymous memory to malloc on the promise
 * that it reads as zero. Replay a delta that only recorded the page moving and
 * it comes back holding what it held BEFORE it was freed - which the guest then
 * hands out as fresh memory. That is a seek backwards on a big core dying a
 * hundred frames later inside somebody's std::map, with nothing to connect the
 * two.
 *
 * The pre-image depends on what the page WAS. One the epoch tracks is captured
 * the way a write would capture it. A free page reads as zero and that is its
 * pre-image. One that is mapped but untracked (read-only, executable) holds
 * real bytes that nothing else will copy, so they are copied here. */
static void epoch_note_status_change(mb_block *b, size_t i, uint8_t to) {
	mb_page *p = &b->pages[i];
	if (!b->epoch_active || p->status == to) return;
	/* The allocation map's half of the delta. Recorded as it happens rather
	 * than found by comparing the whole map against a copy of it taken when the
	 * epoch opened - that copy was half a megabyte a frame on a big machine,
	 * and the comparison was another pass over every page there is. */
	if (!bits_get(b->stat_bits, i)) {
		bits_set(b->stat_bits, i);
		b->epoch_status[i] = p->status;
		b->epoch_nstat++;
	}
	if (p->invisible) return;
	if (epoch_tracks(p)) {
		mb_block_epoch_capture(b, i, mirror_addr(b, b->addr.start + (i << MB_PAGESHIFT)));
		return;
	}
	if (p->epoch_dirty) return;              /* already spoken for this epoch */
	p->epoch_dirty = true;
	bits_set(b->epoch_bits, i);
	b->epoch_ndirty++;
}

/* apply a uniform status to a page range and refresh */
static void set_protections(mb_block *b, size_t pstart, size_t pcount, uint8_t status) {
	for (size_t i = pstart; i < pstart + pcount; i++) epoch_note_status_change(b, i, status);
	for (size_t i = pstart; i < pstart + pcount; i++) note_status(b, i, status);
	refresh_range(b, pstart, pcount);
#ifdef _WIN32
	/* A Windows stack reports nothing, so what it did is found by comparing it
	 * with what it held - and that has to be kept now, while the content still
	 * IS the baseline. See get_stack_dirty. */
	if (status == MB_ST_RWSTACK)
		for (size_t i = pstart; i < pstart + pcount; i++)
			mb_page_maybe_snapshot(&b->pages[i], mirror_addr(b, b->addr.start + (i << MB_PAGESHIFT)));
#endif
}

/* ---- Windows: a stack, read rather than watched ----------------------------
 *
 * Every other page reports its own first write, by faulting. A stack cannot -
 * see mb_page_native_prot - so what a stack did is found by looking at it.
 *
 * The alternative was to call a stack written whether or not it was, which is
 * correct and costs everything: ares gives a Game Boy nineteen coroutines a
 * stack of their own, 2.6MB of them, and all of it went into every delta. Seven
 * hundred frames of history was 268MB where Linux made 110MB, and capturing a
 * frame cost 74% of the run where Linux paid 20%. Almost none of those pages had
 * changed. Reading a few megabytes is nothing beside writing them.
 *
 * Two comparisons, against two baselines. `dirty` means "differs from the
 * sealed image", which is the snapshot taken when the page became a stack.
 * `epoch_dirty` means "changed since the last frame was described", which is
 * the shadow. Both are exact, and both are more honest than a fault bit, which
 * stays set when a page is written and then put back. */
#ifdef _WIN32
static bool stack_page_is_baseline(const mb_page *p, const void *live) {
	if (p->snap_kind == MB_SNAP_DATA) return memcmp(live, p->snap_data, MB_PAGESIZE) == 0;
	if (p->snap_kind == MB_SNAP_ZERO) {
		const uint64_t *w = (const uint64_t *)live;
		for (size_t k = 0; k < MB_PAGESIZE / sizeof(uint64_t); k++) if (w[k]) return false;
		return true;
	}
	return false;  /* no baseline to be equal to */
}
#endif

/* What every stack differs from the baseline in. Must run before anything that
 * READS a page's dirtiness - a savestate, a seal - and before anything that
 * changes a stack page's status, since a page that stops being a stack has to
 * carry the truth out with it. The range form is for those last: a guest
 * allocates constantly and none of it needs the whole set compared. No-op on
 * Linux, where a stack faults like everything else. */
#ifdef _WIN32
static void stack_dirty_page(mb_block *b, size_t i) {
	mb_page *p = &b->pages[i];
	if (p->invisible || p->uncommitted) return;
	set_dirty(b, i, !stack_page_is_baseline(
		p, (const void *)mirror_addr(b, b->addr.start + (i << MB_PAGESHIFT))));
}
#endif

static void get_stack_dirty_range(mb_block *b, size_t ps, size_t pcount) {
#ifdef _WIN32
	if (!b->swapped_in) return;
	for (size_t i = ps; i < ps + pcount; i++)
		if (bits_get(b->stack_bits, i)) stack_dirty_page(b, i);
#else
	(void)b; (void)ps; (void)pcount;
#endif
}

static void get_stack_dirty(mb_block *b) {
#ifdef _WIN32
	if (!b->swapped_in) return;
	for (size_t w = 0; w < b->nwords; w++) {
		uint64_t m = b->stack_bits[w];
		while (m) {
			size_t i = (w << 6) + (size_t)bits_first(m);
			m &= m - 1;
			stack_dirty_page(b, i);
		}
	}
#else
	(void)b;
#endif
}

/* And what each of them did since the last frame was described, which is what
 * this one owes. The shadow is only rewritten where it differs, so a stack page
 * nobody touched costs one comparison and no copying at all - and most of a
 * coroutine stack is never touched.
 *
 * Being a frame behind is the failure this can have, and it is the safe one: a
 * load, or an epoch abandoned without being saved, leaves a shadow describing
 * an older moment, and the page goes into one delta that did not need it. A
 * delta says what a page HOLDS at the end of the frame, so carrying one page
 * too many is waste and never wrong. */
static void get_stack_epoch(mb_block *b) {
#ifdef _WIN32
	if (!b->swapped_in || !b->epoch_active) return;
	for (size_t w = 0; w < b->nwords; w++) {
		uint64_t m = b->stack_bits[w];
		while (m) {
			size_t i = (w << 6) + (size_t)bits_first(m);
			m &= m - 1;
			mb_page *p = &b->pages[i];
			if (!epoch_tracks(p) || p->uncommitted) continue;
			const void *live = (const void *)mirror_addr(b, b->addr.start + (i << MB_PAGESHIFT));
			/* No shadow means nothing has ever compared this page - it was
			 * mapped since - so everything in it is owed. */
			if (p->shadow && memcmp(live, p->shadow, MB_PAGESIZE) == 0) continue;
			if (!p->shadow) p->shadow = snap_alloc();
			if (p->shadow) memcpy(p->shadow, live, MB_PAGESIZE);
			if (p->epoch_dirty) continue;
			p->epoch_dirty = true;
			bits_set(b->epoch_bits, i);
			b->epoch_ndirty++;
		}
	}
#else
	(void)b;
#endif
}

/* ---- allocation ops ---- */

int mb_block_mmap_fixed(mb_block *b, mb_range addr, mb_prot prot, bool no_replace) {
	size_t pcount, ps = validate(b, addr, &pcount);
	if (ps == (size_t)-1) return -EINVAL;
	if (no_replace)
		for (size_t i = ps; i < ps + pcount; i++)
			if (b->pages[i].status != MB_ST_FREE) return -EEXIST;
	set_protections(b, ps, pcount, prot_status(prot));
	return 0;
}


/* A big request is served from the TOP of the arena, a small one from the
 * bottom. Best fit alone is not enough over a long run: a machine that
 * compiles code takes a few hundred megabytes, gives them back, and takes
 * them again a hundred times, between thousands of small allocations. The
 * small ones eventually land inside a returned big hole, and from then on no
 * big request fits although gigabytes are free. Keeping the two ends apart
 * costs nothing and keeps the large holes whole.
 *
 * "Big" is a size no ordinary allocation reaches; the arena has room for many
 * of them either way. */
#define MB_BIG_REQUEST_PAGES (4096) /* 16 MiB */

/* best-fit free run inside an arena; returns start page index or SIZE_MAX */
static size_t find_free_pages(mb_block *b, size_t arena_start, size_t arena_count, size_t npages) {
	size_t end = arena_start + arena_count;
	if (npages >= MB_BIG_REQUEST_PAGES) {
		/* the highest run that fits, so the low end stays free for the rest */
		size_t i = end, run_end = end;
		while (i > arena_start) {
			i--;
			if (b->pages[i].status != MB_ST_FREE) { run_end = i; continue; }
			if (run_end - i >= npages) return run_end - npages;
		}
		return (size_t)-1;
	}
	size_t best = (size_t)-1, best_len = (size_t)-1;
	size_t i = arena_start;
	while (i < end) {
		if (b->pages[i].status == MB_ST_FREE) {
			size_t j = i;
			while (j < end && b->pages[j].status == MB_ST_FREE) j++;
			size_t len = j - i;
			if (len >= npages && len < best_len) { best = i; best_len = len; }
			i = j;
		} else i++;
	}
	return best;
}

mb_sword mb_block_mmap(mb_block *b, mb_range addr, mb_prot prot, mb_range arena, bool no_replace) {
	if (addr.size == 0) return -EINVAL;
	if (addr.start == 0) {
		if (addr.size != mb_align_down(addr.size)) return -EINVAL;
		size_t acount, as = validate(b, arena, &acount);
		if (as == (size_t)-1) return -EINVAL;
		size_t ps = find_free_pages(b, as, acount, addr.size >> MB_PAGESHIFT);
		if (ps == (size_t)-1) {
			/* A refusal here is a machine dying for want of address space, and
			 * "out of memory" alone never says whether the arena is full or
			 * merely in pieces. Say which. */
			size_t freeP = 0, run = 0, best = 0;
			for (size_t i = as; i < as + acount; i++) {
				if (b->pages[i].status == MB_ST_FREE) { freeP++; run++; if (run > best) best = run; }
				else run = 0;
			}
			mb_diag_banner("arena exhausted");
			mb_diag("[mmap] %zu MiB wanted; arena %zu MiB, %zu MiB free, largest run %zu MiB\n",
			        (size_t)(addr.size >> 20), (size_t)((acount << MB_PAGESHIFT) >> 20),
			        (size_t)((freeP << MB_PAGESHIFT) >> 20), (size_t)((best << MB_PAGESHIFT) >> 20));
			/* and what is holding it: the largest occupied runs, which is
			 * usually one or two structures a core reserved and never gave back */
			for (int shown = 0; shown < 6; shown++) {
				size_t bs = 0, bl = 0, i = as;
				static size_t reported[6]; /* skip the ones already named */
				while (i < as + acount) {
					if (b->pages[i].status == MB_ST_FREE) { i++; continue; }
					size_t j = i;
					while (j < as + acount && b->pages[j].status != MB_ST_FREE) j++;
					bool seen = false;
					for (int k = 0; k < shown; k++) if (reported[k] == i) seen = true;
					if (!seen && j - i > bl) { bl = j - i; bs = i; }
					i = j;
				}
				if (bl == 0) break;
				reported[shown] = bs;
				mb_diag("[mmap]   %zu MiB at +%zu MiB\n", (size_t)((bl << MB_PAGESHIFT) >> 20),
				        (size_t)(((bs - as) << MB_PAGESHIFT) >> 20));
			}
			return -ENOMEM;
		}
		set_protections(b, ps, addr.size >> MB_PAGESHIFT, prot_status(prot));
		return (mb_sword)(b->addr.start + (ps << MB_PAGESHIFT));
	} else {
		int r = mb_block_mmap_fixed(b, addr, prot, no_replace);
		return r != 0 ? r : (mb_sword)addr.start;
	}
}

int mb_block_mprotect(mb_block *b, mb_range addr, mb_prot prot) {
	size_t pcount, ps = validate(b, addr, &pcount);
	if (ps == (size_t)-1) return -EINVAL;
	get_stack_dirty_range(b, ps, pcount);
	for (size_t i = ps; i < ps + pcount; i++)
		if (b->pages[i].status == MB_ST_FREE) return -ENOMEM;
	set_protections(b, ps, pcount, prot_status(prot));
	return 0;
}

/* zero + free (munmap) or keep-allocated (madvise dontneed) */
static void free_pages(mb_block *b, size_t ps, size_t pcount, bool advise_only) {
	for (size_t i = ps; i < ps + pcount; i++) {
		uintptr_t maddr = mirror_addr(b, b->addr.start + (i << MB_PAGESHIFT));
		mb_page_maybe_snapshot(&b->pages[i], maddr);
		/* before the memset below, not after: an open epoch's pre-image of this
		 * page is what it held while the guest still had it */
		epoch_note_status_change(b, i, MB_ST_FREE);
		if (!b->pages[i].uncommitted) memset((void *)maddr, 0, MB_PAGESIZE);
		/* undirty pages whose sealed baseline was already zero */
		set_dirty(b, i, !b->pages[i].invisible && b->pages[i].snap_kind != MB_SNAP_ZERO);
	}
	if (advise_only) refresh_range(b, ps, pcount);
	else set_protections(b, ps, pcount, MB_ST_FREE);
}

static int munmap_impl(mb_block *b, mb_range addr, bool advise_only) {
	size_t pcount, ps = validate(b, addr, &pcount);
	if (ps == (size_t)-1) return -EINVAL;
	get_stack_dirty_range(b, ps, pcount);
	for (size_t i = ps; i < ps + pcount; i++)
		if (b->pages[i].status == MB_ST_FREE) return -EINVAL;
	free_pages(b, ps, pcount, advise_only);
	return 0;
}

int mb_block_munmap(mb_block *b, mb_range addr) { return munmap_impl(b, addr, false); }
int mb_block_madvise_dontneed(mb_block *b, mb_range addr) { return munmap_impl(b, addr, true); }

/* in-place mremap only (grow needs following pages free; shrink munmaps tail) */
mb_sword mb_block_mremap(mb_block *b, mb_range addr, uintptr_t new_size, mb_range arena) {
	(void)arena;
	if (addr.size == 0 || new_size == 0) return -EINVAL;
	if (addr.start == 0) return -ENOSYS; /* move path unreachable in the reference */
	size_t pcount, ps = validate(b, addr, &pcount);
	if (ps == (size_t)-1) return -EINVAL;
	if (new_size > addr.size) {
		mb_range full = { addr.start, new_size };
		size_t fcount, fs = validate(b, full, &fcount);
		if (fs == (size_t)-1) return -EINVAL;
		for (size_t i = ps; i < ps + pcount; i++)
			if (b->pages[i].status == MB_ST_FREE) return -EINVAL;
		for (size_t i = ps + pcount; i < fs + fcount; i++)
			if (b->pages[i].status != MB_ST_FREE) return -EEXIST;
		set_protections(b, ps + pcount, fcount - pcount, b->pages[ps].status);
		return (mb_sword)addr.start;
	} else {
		for (size_t i = ps; i < ps + pcount; i++)
			if (b->pages[i].status == MB_ST_FREE) return -EINVAL;
		mb_range tail = { addr.start + new_size, addr.size - new_size };
		int r = munmap_impl(b, tail, false);
		return r != 0 ? r : (mb_sword)addr.start;
	}
}

int mb_block_mark_invisible(mb_block *b, mb_range addr) {
	if (b->sealed) { fprintf(stderr, "miniBox: mark_invisible after seal\n"); return -EINVAL; }
	size_t pcount, ps = validate(b, addr, &pcount);
	if (ps == (size_t)-1) return -EINVAL;
	for (size_t i = ps; i < ps + pcount; i++) { set_dirty(b, i, true); b->pages[i].invisible = true; }
	refresh_range(b, ps, pcount);
	return 0;
}

int mb_block_copy_from_external(mb_block *b, const uint8_t *src, uintptr_t start, uintptr_t len) {
	mb_range r = { start, len };
	mb_range e = mb_range_align_expand(r);
	size_t pcount, ps = validate(b, e, &pcount);
	if (ps == (size_t)-1) return -EINVAL;
	for (size_t i = ps; i < ps + pcount; i++) { set_dirty(b, i, true); page_cool(b, i); }
	ensure_committed(b, ps, pcount);
	memcpy((void *)mirror_addr(b, start), src, len);
	return 0;
}

/* ---- seal ---- */

int mb_block_seal(mb_block *b) {
	if (b->sealed) { fprintf(stderr, "miniBox: already sealed\n"); return -EINVAL; }
	get_stack_dirty(b);
	/* the baseline is about to become the live image, so any epoch measured
	 * against the old one is meaningless */
	mb_block_epoch_clear(b);
	for (size_t i = 0; i < b->npages; i++) {
		if (b->pages[i].dirty && !b->pages[i].invisible) {
			page_cool(b, i);
			set_dirty(b, i, false);
			snap_release(b->pages[i].snap_data);
			b->pages[i].snap_data = NULL;
			b->pages[i].snap_kind = MB_SNAP_NONE; /* live memory is the baseline */
#ifdef _WIN32
			/* except a Windows stack, which keeps a baseline of its own: nothing
			 * will report its writes, so they are found by comparing against it
			 * (as in set_protections) */
			if (b->pages[i].status == MB_ST_RWSTACK)
				mb_page_maybe_snapshot(&b->pages[i], mirror_addr(b, b->addr.start + (i << MB_PAGESHIFT)));
#endif
		}
	}
	refresh_all(b);
	b->sealed = true;

	mb_sha256 sh;
	mb_sha256_init(&sh);
	mb_sha256_update(&sh, &b->addr, sizeof(b->addr));
	for (size_t i = 0; i < b->npages; i++) {
		int32_t tag;
		switch (b->pages[i].snap_kind) {
			case MB_SNAP_NONE: tag = 1; mb_sha256_update(&sh, &tag, sizeof(tag)); break;
			case MB_SNAP_ZERO: tag = 2; mb_sha256_update(&sh, &tag, sizeof(tag)); break;
			case MB_SNAP_DATA: mb_sha256_update(&sh, b->pages[i].snap_data, MB_PAGESIZE); break;
		}
	}
	mb_sha256_final(&sh, b->hash);
	return 0;
}

/* ---- introspection ---- */

size_t mb_block_page_len(const mb_block *b) { return b->npages; }

/* The sealed baseline's identity: what every clean page reads back as. Two
 * machines that disagree here cannot exchange states, however alike their
 * configuration looks - which is why anything CACHING states across sessions
 * has to key them on this and not on the core's name and settings. */
const uint8_t *mb_block_hash(const mb_block *b) { return b->hash; }

uint8_t mb_block_page_info(mb_block *b, size_t i) {
	/* A Windows stack reports nothing, so the answer is only true once this has
	 * looked - and an introspection call that can be stale is worse than a page
	 * compared. One page, not the whole set. */
	get_stack_dirty_range(b, i, 1);
	const mb_page *p = &b->pages[i];
	uint8_t res = p->status; /* status bytes already match page_info's low bits */
	if (p->dirty) res |= 0x80;
	if (p->invisible) res |= 0x40;
	return res;
}

/* ---- savestate (see docs/docs/MACHINE-SPEC.md section 6) ---- */

static const char MAGIC[] = "ActivatedMemoryBlock";

static int wr(mb_write_cb w, uintptr_t ud, const void *data, uintptr_t n) {
	return w(ud, (const uint8_t *)data, n) < 0 ? -EIO : 0;
}
static int rd(mb_read_cb r, uintptr_t ud, void *data, uintptr_t n) {
	uint8_t *p = (uint8_t *)data;
	while (n) {
		intptr_t got = r(ud, p, n);
		if (got <= 0) return -EIO;
		p += got; n -= (uintptr_t)got;
	}
	return 0;
}

int mb_block_save_state(mb_block *b, mb_write_cb w, uintptr_t ud) {
	if (!b->sealed) return -EINVAL;
	get_stack_dirty(b);
	if (wr(w, ud, MAGIC, sizeof(MAGIC) - 1)) return -EIO;
	if (wr(w, ud, b->hash, 32)) return -EIO;
	if (wr(w, ud, &b->addr, sizeof(b->addr))) return -EIO;
	/* The status and dirty arrays go out as two blocks, not two callbacks per
	 * page. The write callback crosses into the host language (a managed delegate
	 * for the C# frontend), so a per-byte loop over a 272MB layout is ~139,000
	 * marshalled calls per state - which, with rewind taking a state every frame,
	 * cost more than the emulation itself. The bytes on the wire are unchanged, so
	 * existing savestates still load (the reader already reads them in bulk). */
	if (wr(w, ud, b->status_map, b->npages)) return -EIO;
	if (wr(w, ud, b->dirty_map, b->npages)) return -EIO;
	for (size_t i = 0; i < b->npages; i++) {
		if (!b->pages[i].invisible && b->pages[i].dirty) {
			uintptr_t maddr = mirror_addr(b, b->addr.start + (i << MB_PAGESHIFT));
			ensure_committed(b, i, 1);
			if (wr(w, ud, (const void *)maddr, MB_PAGESIZE)) return -EIO;
		}
	}
	return 0;
}

int mb_block_load_state(mb_block *b, mb_read_cb r, uintptr_t ud) {
	if (!b->sealed) return -EINVAL;
	get_stack_dirty(b);
	/* the load replaces the machine, so an open epoch no longer describes it */
	mb_block_epoch_clear(b);
	char magic[sizeof(MAGIC) - 1];
	if (rd(r, ud, magic, sizeof(magic))) return -EIO;
	if (memcmp(magic, MAGIC, sizeof(magic)) != 0) return -EINVAL;
	uint8_t hash[32];
	if (rd(r, ud, hash, 32)) return -EIO;
	if (memcmp(hash, b->hash, 32) != 0) {
		/* This state was made by a different machine. It used to say so and
		 * load it anyway, which cannot work and does not fail where it happens:
		 * a savestate carries only the DIRTY pages and every clean one is read
		 * back from the sealed baseline, so a state from another baseline
		 * assembles a machine out of two different ones. It runs. It crashes
		 * later, somewhere unrelated - measured on PS2 as a null dereference
		 * inside std::_Rb_tree_rebalance_for_erase, sixty frames after the load
		 * and with nothing left to connect the two.
		 *
		 * So it is refused. A caller whose states are a CACHE (Chimera's
		 * greenzone) should be throwing them away at this point, and a refusal
		 * is what tells it to. */
		mb_diag_banner("state hash mismatch");
		mb_diag("[state] refused: this state was made by another machine\n[state]   state ");
		for (int i = 0; i < 8; i++) mb_diag("%02x", hash[i]);
		mb_diag("\n[state]   block ");
		for (int i = 0; i < 8; i++) mb_diag("%02x", b->hash[i]);
		mb_diag("\n");
		return -EINVAL;
	}
	mb_range addr;
	if (rd(r, ud, &addr, sizeof(addr))) return -EIO;
	if (addr.start != b->addr.start || addr.size != b->addr.size) return -EINVAL;

	uint8_t *statii = (uint8_t *)malloc(b->npages);
	uint8_t *dirtii = (uint8_t *)malloc(b->npages);
	if (rd(r, ud, statii, b->npages) || rd(r, ud, dirtii, b->npages)) { free(statii); free(dirtii); return -EIO; }

	/* Proportional to what the load CHANGES, not to the arena.
	 *
	 * Two things used to be proportional to the arena. Re-protecting every page
	 * after the load: a 272MB layout is 69,632 pages, walked and re-protected
	 * per frame under rewind or a rerecord replay, so now only the pages whose
	 * protection actually changes get a syscall, in runs. And finding those
	 * pages: the walk that compared the state's maps against the page array
	 * read forty bytes a page to learn that the page was clean in both and had
	 * not moved, which on the ares arena was half a million pages and three
	 * milliseconds an anchor, most of the anchor's cost. The packed maps make
	 * that comparison a word at a time, so a run of eight such pages costs two
	 * loads and nothing else. */
	prot_run run = { 0, 0, false };
	size_t i = 0;
	while (i < b->npages) {
		if ((i & 7) == 0 && i + 8 <= b->npages) {
			uint64_t ds, dm, ss, sm;
			memcpy(&ds, dirtii + i, sizeof ds);
			memcpy(&dm, b->dirty_map + i, sizeof dm);
			memcpy(&ss, statii + i, sizeof ss);
			memcpy(&sm, b->status_map + i, sizeof sm);
			if ((ds | dm) == 0 && ss == sm) { i += 8; continue; }
		}
		if (dirtii[i] == 0 && b->dirty_map[i] == 0 && statii[i] == b->status_map[i]) { i++; continue; }
		mb_page *p = &b->pages[i];
		mb_prot prot_before = mb_page_native_prot(p);
		if (!p->invisible) {
			bool old_d = p->dirty, new_d = dirtii[i] != 0;
			uintptr_t maddr = mirror_addr(b, b->addr.start + (i << MB_PAGESHIFT));
			if (old_d || new_d) ensure_committed(b, i, 1);
			if (!old_d && new_d) {
				mb_page_maybe_snapshot(p, maddr);
				if (rd(r, ud, (void *)maddr, MB_PAGESIZE)) { free(statii); free(dirtii); return -EIO; }
			} else if (old_d && !new_d) {
				if (p->snap_kind == MB_SNAP_ZERO) memset((void *)maddr, 0, MB_PAGESIZE);
				else if (p->snap_kind == MB_SNAP_DATA) memcpy((void *)maddr, p->snap_data, MB_PAGESIZE);
				else { free(statii); free(dirtii); fprintf(stderr, "miniBox: missing snapshot for dirty region\n"); return -EINVAL; }
			} else if (old_d && new_d) {
				if (rd(r, ud, (void *)maddr, MB_PAGESIZE)) { free(statii); free(dirtii); return -EIO; }
			}
			set_dirty(b, i, new_d);
			/* a hot page just rewritten keeps its shadow true; one made clean
			 * cools, because a clean page is held for the baseline's sake */
			if (p->hot) {
				if (new_d) memcpy(p->shadow, (const void *)maddr, MB_PAGESIZE);
				else page_cool(b, i);
			}
		}
		note_status(b, i, statii[i]);
		if (mb_page_native_prot(p) != prot_before) run_note(b, &run, i);
		i++;
	}
	run_close(b, &run);
	free(statii); free(dirtii);
	return 0;
}

/* ---- epochs and deltas (see minibox_internal.h) ---- */

static const char DELTA_MAGIC[] = "MiniBoxDelta1";

/* Forget what an epoch knew about one page, returning its pre-image. */
static void epoch_clear_page(mb_page *p) {
	p->epoch_dirty = false;
	p->epoch_hold = false;
}

/* Forgets the whole of the last epoch, visiting only the pages it touched. */
static void epoch_forget(mb_block *b) {
	for (size_t w = 0; w < b->nwords; w++) {
		uint64_t m = b->epoch_bits[w];
		while (m) {
			epoch_clear_page(&b->pages[(w << 6) + (size_t)bits_first(m)]);
			m &= m - 1;
		}
	}
	bits_none(b, b->epoch_bits);
	bits_none(b, b->stat_bits);
	b->epoch_ndirty = 0;
	b->epoch_nstat = 0;
}

void mb_block_epoch_clear(mb_block *b) {
	epoch_forget(b);
	b->epoch_active = false;
}

/* Is this a page an epoch tracks at all? Invisible pages are excluded for the
 * same reason savestates exclude them - they are not machine state - and a free
 * page has nothing to say. */
static bool epoch_tracks(const mb_page *p) {
	return !p->invisible
		&& (p->status == MB_ST_RW || p->status == MB_ST_RWX || p->status == MB_ST_RWSTACK);
}

/* Opens an epoch: from here, what changed is answerable per frame.
 *
 * Two things have to happen and neither may walk the arena. The last epoch's
 * per-page state is forgotten, which touches only the pages it wrote. And the
 * pages that are mapped WRITABLE are protected again so their next write
 * faults - which is only ever the pages written since the last epoch opened,
 * because everything else is still protected from that one. The old version
 * set a flag on every tracked page and then re-protected every page that had
 * ever been written, both proportional to the arena and most of the cost of a
 * captured frame.
 *
 * A clean page needs neither: it is already read-only for the baseline's sake,
 * its write already faults, and that fault records the epoch's pre-image too.
 * The hold exists only to make a DIRTY page - one already mapped writable -
 * fault once more. */
int mb_block_epoch_begin(mb_block *b) {
	if (!b->sealed) return -EINVAL;
	epoch_forget(b);
	b->epoch_active = true;   /* before the refresh below: it reads the holds */
	b->epoch_no++;
	/* the hot pages as this epoch finds them, for the comparison at its end */
	for (size_t w = 0; w < b->nwords; w++) {
		uint64_t m = b->hot_bits[w];
		while (m) {
			size_t i = (w << 6) + (size_t)bits_first(m);
			m &= m - 1;
			memcpy(b->pages[i].shadow, (const void *)mirror_addr(b, b->addr.start + (i << MB_PAGESHIFT)), MB_PAGESIZE);
		}
	}

	size_t run_start = (size_t)-1, run_last = 0;
	for (size_t w = 0; w < b->nwords; w++) {
		uint64_t m = b->unheld_bits[w];
		if (!m) continue;
		/* Taken now, because refreshing a run below re-records what it applied
		 * and may legitimately set bits in this word again. */
		b->unheld_bits[w] = 0;
		while (m) {
			size_t i = (w << 6) + (size_t)bits_first(m);
			m &= m - 1;
			mb_page *p = &b->pages[i];
			if (epoch_tracks(p)) {
				p->epoch_hold = true;
			}
			/* maximal runs, so the syscalls are as few as the pages allow */
			if (run_start == (size_t)-1) { run_start = run_last = i; }
			else if (i == run_last + 1) { run_last = i; }
			else { refresh_range(b, run_start, run_last - run_start + 1); run_start = run_last = i; }
		}
	}
	if (run_start != (size_t)-1) refresh_range(b, run_start, run_last - run_start + 1);
	return 0;
}

size_t mb_block_epoch_page_count(const mb_block *b) { return b->epoch_ndirty; }

int mb_block_delta_save(mb_block *b, bool forward, mb_write_cb w, uintptr_t ud) {
	if (!b->epoch_active) return -EINVAL;
	get_stack_epoch(b);
	get_hot_epoch(b);

	/* What the allocation map did, so applying a delta lands on the same shape
	 * of machine and not merely the same bytes. */
	/* Forwards only. A delta used to be saveable backwards as well, so that a
	 * frontend could step back a frame by undoing it; keeping that possible
	 * meant copying every page a frame wrote, inside the fault handler, for
	 * every frame - and nothing asked, because a frame is reached by loading an
	 * anchor and applying the deltas since it. Refused rather than quietly
	 * answered with zeros. */
	if (!forward) return -ENOTSUP;

	uint64_t nstatus = b->epoch_nstat;
	uint64_t npages64 = b->npages, ndata = b->epoch_ndirty;
	if (wr(w, ud, DELTA_MAGIC, sizeof(DELTA_MAGIC) - 1)) return -EIO;
	if (wr(w, ud, &npages64, sizeof(npages64))) return -EIO;
	if (wr(w, ud, &nstatus, sizeof(nstatus))) return -EIO;
	for (size_t bw = 0; bw < b->nwords; bw++) {
		uint64_t m = b->stat_bits[bw];
		while (m) {
			size_t i = (bw << 6) + (size_t)bits_first(m);
			m &= m - 1;
			uint64_t idx = i;
			uint8_t st = b->pages[i].status;
			if (wr(w, ud, &idx, sizeof(idx)) || wr(w, ud, &st, 1)) return -EIO;
		}
	}

	if (wr(w, ud, &ndata, sizeof(ndata))) return -EIO;
	for (size_t bw = 0; bw < b->nwords; bw++) {
		uint64_t m = b->epoch_bits[bw];
		while (m) {
			size_t i = (bw << 6) + (size_t)bits_first(m);
			m &= m - 1;
			uint64_t idx = i;
			if (wr(w, ud, &idx, sizeof(idx))) return -EIO;
			ensure_committed(b, i, 1);   /* the live page, as the frame left it */
			if (wr(w, ud, (const void *)mirror_addr(b, b->addr.start + (i << MB_PAGESHIFT)), MB_PAGESIZE)) return -EIO;
		}
	}
	heat_written_pages(b);
	return 0;
}

/* ---- composing two deltas ----
 *
 * A delta's two lists are written in ascending page order (both loops above
 * walk the block), so composing is a merge of sorted runs. Held in memory
 * rather than streamed because the counts are written before the entries and a
 * write callback cannot be seeked back to; a delta is the frame's churn, which
 * is megabytes, not the machine.
 */

typedef struct {
	uint64_t npages;
	uint64_t nstatus;
	uint64_t *sidx;
	uint8_t *sval;
	uint64_t ndata;
	uint64_t *didx;
	uint8_t *data;   /* ndata * MB_PAGESIZE */
} delta_parts;

static void parts_free(delta_parts *d) {
	free(d->sidx); free(d->sval); free(d->didx); free(d->data);
	memset(d, 0, sizeof(*d));
}

static int parts_read(mb_read_cb r, uintptr_t ud, delta_parts *d) {
	memset(d, 0, sizeof(*d));
	char magic[sizeof(DELTA_MAGIC) - 1];
	if (rd(r, ud, magic, sizeof(magic))) return -EIO;
	if (memcmp(magic, DELTA_MAGIC, sizeof(magic)) != 0) return -EINVAL;
	if (rd(r, ud, &d->npages, sizeof(d->npages))) return -EIO;
	if (rd(r, ud, &d->nstatus, sizeof(d->nstatus))) return -EIO;
	if (d->nstatus > d->npages) return -EINVAL;
	if (d->nstatus) {
		d->sidx = malloc(d->nstatus * sizeof(uint64_t));
		d->sval = malloc(d->nstatus);
		if (!d->sidx || !d->sval) { parts_free(d); return -ENOMEM; }
	}
	for (uint64_t k = 0; k < d->nstatus; k++) {
		if (rd(r, ud, &d->sidx[k], sizeof(uint64_t)) || rd(r, ud, &d->sval[k], 1)) { parts_free(d); return -EIO; }
		if (d->sidx[k] >= d->npages) { parts_free(d); return -EINVAL; }
	}
	if (rd(r, ud, &d->ndata, sizeof(d->ndata))) { parts_free(d); return -EIO; }
	if (d->ndata > d->npages) { parts_free(d); return -EINVAL; }
	if (d->ndata) {
		d->didx = malloc(d->ndata * sizeof(uint64_t));
		d->data = malloc(d->ndata * MB_PAGESIZE);
		if (!d->didx || !d->data) { parts_free(d); return -ENOMEM; }
	}
	for (uint64_t k = 0; k < d->ndata; k++) {
		if (rd(r, ud, &d->didx[k], sizeof(uint64_t))
			|| rd(r, ud, d->data + k * MB_PAGESIZE, MB_PAGESIZE)) { parts_free(d); return -EIO; }
		if (d->didx[k] >= d->npages) { parts_free(d); return -EINVAL; }
	}
	return 0;
}

/* how many entries a merge of two ascending index runs produces */
static uint64_t merged_count(const uint64_t *a, uint64_t na, const uint64_t *b, uint64_t nb) {
	uint64_t i = 0, j = 0, n = 0;
	while (i < na && j < nb) {
		if (a[i] < b[j]) i++;
		else if (b[j] < a[i]) j++;
		else { i++; j++; }
		n++;
	}
	return n + (na - i) + (nb - j);
}

/* ---- composing two deltas that are already in memory --------------------
 *
 * The streaming version above reads both deltas into buffers of its own before
 * it can merge them, because a count is written before its list and a write
 * callback cannot be seeked back to. That is the right shape for a delta coming
 * off a disk. It is the wrong shape for the caller that actually does this
 * every frame: the history holds both deltas as contiguous bytes already, so
 * reading them in means copying two megabytes to look at two megabytes.
 *
 * This walks them where they lie. Nothing is allocated, each byte of input is
 * read once, and each byte of output is written once - a third of the memory
 * traffic for the same answer.
 */
typedef struct {
	uint64_t npages, nstatus, ndata;
	const uint8_t *status;   /* nstatus entries: u64 index, u8 value */
	const uint8_t *data;     /* ndata entries: u64 index, MB_PAGESIZE bytes */
} delta_view;

#define DELTA_STATUS_STRIDE (sizeof(uint64_t) + 1)
#define DELTA_DATA_STRIDE   (sizeof(uint64_t) + MB_PAGESIZE)

static uint64_t view_idx(const uint8_t *entry) {
	uint64_t v;
	memcpy(&v, entry, sizeof v);
	return v;
}

/* Bounds-checked because a delta can come from a file somebody edited. */
static int view_open(const uint8_t *buf, size_t len, delta_view *v) {
	const size_t head = sizeof(DELTA_MAGIC) - 1;
	if (len < head + 3 * sizeof(uint64_t)) return -EINVAL;
	if (memcmp(buf, DELTA_MAGIC, head) != 0) return -EINVAL;
	const uint8_t *p = buf + head;
	memcpy(&v->npages, p, sizeof(uint64_t)); p += sizeof(uint64_t);
	memcpy(&v->nstatus, p, sizeof(uint64_t)); p += sizeof(uint64_t);
	if (v->nstatus > v->npages) return -EINVAL;
	size_t left = len - (size_t)(p - buf);
	if (v->nstatus > left / DELTA_STATUS_STRIDE) return -EINVAL;
	v->status = p;
	p += (size_t)v->nstatus * DELTA_STATUS_STRIDE;
	if ((size_t)(p - buf) + sizeof(uint64_t) > len) return -EINVAL;
	memcpy(&v->ndata, p, sizeof(uint64_t)); p += sizeof(uint64_t);
	if (v->ndata > v->npages) return -EINVAL;
	left = len - (size_t)(p - buf);
	if (v->ndata > left / DELTA_DATA_STRIDE) return -EINVAL;
	v->data = p;
	return 0;
}

/* How many entries a sorted merge of two index lists produces. */
static uint64_t view_merged(const uint8_t *a, uint64_t na, const uint8_t *b, uint64_t nb, size_t stride) {
	uint64_t n = 0, i = 0, j = 0;
	while (i < na || j < nb) {
		if (i >= na) { j++; }
		else if (j >= nb) { i++; }
		else {
			uint64_t ia = view_idx(a + i * stride), ib = view_idx(b + j * stride);
			if (ia == ib) { i++; j++; }
			else if (ia < ib) i++;
			else j++;
		}
		n++;
	}
	return n;
}

int mb_block_delta_compose_mem(const uint8_t *abuf, size_t alen, const uint8_t *bbuf, size_t blen,
                               mb_write_cb w, uintptr_t ud, size_t *b_used) {
	delta_view a, b;
	int rc = view_open(abuf, alen, &a);
	if (rc) return rc;
	rc = view_open(bbuf, blen, &b);
	if (rc) return rc;
	if (a.npages != b.npages) return -EINVAL;

	uint64_t nstatus = view_merged(a.status, a.nstatus, b.status, b.nstatus, DELTA_STATUS_STRIDE);
	uint64_t ndata = view_merged(a.data, a.ndata, b.data, b.ndata, DELTA_DATA_STRIDE);
	if (wr(w, ud, DELTA_MAGIC, sizeof(DELTA_MAGIC) - 1)) return -EIO;
	if (wr(w, ud, &a.npages, sizeof(a.npages))) return -EIO;

	if (wr(w, ud, &nstatus, sizeof(nstatus))) return -EIO;
	for (uint64_t i = 0, j = 0; i < a.nstatus || j < b.nstatus; ) {
		/* where both moved the same page, the later allocation map is the one
		 * the composed delta has to land on */
		bool takeB = i >= a.nstatus
			|| (j < b.nstatus && view_idx(b.status + j * DELTA_STATUS_STRIDE) <= view_idx(a.status + i * DELTA_STATUS_STRIDE));
		const uint8_t *e = takeB ? b.status + j * DELTA_STATUS_STRIDE : a.status + i * DELTA_STATUS_STRIDE;
		uint64_t idx = view_idx(e);
		if (takeB) { if (i < a.nstatus && view_idx(a.status + i * DELTA_STATUS_STRIDE) == idx) i++; j++; } else i++;
		if (wr(w, ud, e, DELTA_STATUS_STRIDE)) return -EIO;
	}

	if (wr(w, ud, &ndata, sizeof(ndata))) return -EIO;
	for (uint64_t i = 0, j = 0; i < a.ndata || j < b.ndata; ) {
		bool takeB = i >= a.ndata
			|| (j < b.ndata && view_idx(b.data + j * DELTA_DATA_STRIDE) <= view_idx(a.data + i * DELTA_DATA_STRIDE));
		const uint8_t *e = takeB ? b.data + j * DELTA_DATA_STRIDE : a.data + i * DELTA_DATA_STRIDE;
		uint64_t idx = view_idx(e);
		if (takeB) { if (i < a.ndata && view_idx(a.data + i * DELTA_DATA_STRIDE) == idx) i++; j++; } else i++;
		/* index and page in one write: they are already adjacent in the source */
		if (wr(w, ud, e, DELTA_DATA_STRIDE)) return -EIO;
	}
	/* Where the later delta's own bytes end - what follows them belongs to
	 * whoever wrapped it, and is theirs to pass through. */
	if (b_used != NULL) *b_used = (size_t)(b.data - bbuf) + (size_t)b.ndata * DELTA_DATA_STRIDE;
	return 0;
}

int mb_block_delta_compose(mb_read_cb ra, uintptr_t uda, mb_read_cb rb, uintptr_t udb,
                           mb_write_cb w, uintptr_t ud) {
	delta_parts a, b;
	int rc = parts_read(ra, uda, &a);
	if (rc) return rc;
	rc = parts_read(rb, udb, &b);
	if (rc) { parts_free(&a); return rc; }
	if (a.npages != b.npages) { parts_free(&a); parts_free(&b); return -EINVAL; }

	rc = -EIO;
	uint64_t nstatus = merged_count(a.sidx, a.nstatus, b.sidx, b.nstatus);
	uint64_t ndata = merged_count(a.didx, a.ndata, b.didx, b.ndata);
	if (wr(w, ud, DELTA_MAGIC, sizeof(DELTA_MAGIC) - 1)) goto done;
	if (wr(w, ud, &a.npages, sizeof(a.npages))) goto done;

	if (wr(w, ud, &nstatus, sizeof(nstatus))) goto done;
	for (uint64_t i = 0, j = 0; i < a.nstatus || j < b.nstatus; ) {
		/* where both moved the same page, the later allocation map is the one
		 * the composed delta has to land on */
		bool takeB = i >= a.nstatus || (j < b.nstatus && b.sidx[j] <= a.sidx[i]);
		uint64_t idx = takeB ? b.sidx[j] : a.sidx[i];
		uint8_t s = takeB ? b.sval[j] : a.sval[i];
		if (takeB) { if (i < a.nstatus && a.sidx[i] == idx) i++; j++; } else i++;
		if (wr(w, ud, &idx, sizeof(idx)) || wr(w, ud, &s, 1)) goto done;
	}

	if (wr(w, ud, &ndata, sizeof(ndata))) goto done;
	for (uint64_t i = 0, j = 0; i < a.ndata || j < b.ndata; ) {
		bool takeB = i >= a.ndata || (j < b.ndata && b.didx[j] <= a.didx[i]);
		uint64_t idx = takeB ? b.didx[j] : a.didx[i];
		const uint8_t *page = takeB ? b.data + j * MB_PAGESIZE : a.data + i * MB_PAGESIZE;
		if (takeB) { if (i < a.ndata && a.didx[i] == idx) i++; j++; } else i++;
		if (wr(w, ud, &idx, sizeof(idx)) || wr(w, ud, page, MB_PAGESIZE)) goto done;
	}
	rc = 0;
done:
	parts_free(&a);
	parts_free(&b);
	return rc;
}

/* Applies one frame's delta on top of the machine as it stands.
 *
 * Proportional to the delta, not to the arena. This used to end by
 * re-protecting every page there is, which on a 2GB arena was half a million
 * protection lookups and however many syscalls the map coalesced to - measured
 * at 2.3ms for a delta of sixteen pages, and paid once per delta in a chain, so
 * a seek that applied thirty of them spent seventy milliseconds refreshing
 * pages the deltas never mentioned. Only the pages in the two lists can have
 * changed protection, so only those are looked at, and only the ones whose
 * protection actually moved are told to the OS. */
int mb_block_delta_apply(mb_block *b, mb_read_cb r, uintptr_t ud) {
	if (!b->sealed) return -EINVAL;
	char magic[sizeof(DELTA_MAGIC) - 1];
	if (rd(r, ud, magic, sizeof(magic))) return -EIO;
	if (memcmp(magic, DELTA_MAGIC, sizeof(magic)) != 0) return -EINVAL;

	uint64_t npages64 = 0, nstatus = 0, ndata = 0;
	if (rd(r, ud, &npages64, sizeof(npages64))) return -EIO;
	if (npages64 != b->npages) return -EINVAL;  /* a delta of another machine */
	if (rd(r, ud, &nstatus, sizeof(nstatus))) return -EIO;
	prot_run run = { 0, 0, false };
	for (uint64_t k = 0; k < nstatus; k++) {
		uint64_t idx = 0; uint8_t s = 0;
		if (rd(r, ud, &idx, sizeof(idx)) || rd(r, ud, &s, 1)) return -EIO;
		if (idx >= b->npages) return -EINVAL;
		mb_page *p = &b->pages[idx];
		const mb_prot before = mb_page_native_prot(p);
		note_status(b, (size_t)idx, s);
		if (mb_page_native_prot(p) != before) run_note(b, &run, (size_t)idx);
	}
	run_close(b, &run);

	if (rd(r, ud, &ndata, sizeof(ndata))) return -EIO;
	for (uint64_t k = 0; k < ndata; k++) {
		uint64_t idx = 0;
		if (rd(r, ud, &idx, sizeof(idx))) return -EIO;
		if (idx >= b->npages) return -EINVAL;
		mb_page *p = &b->pages[idx];
		const mb_prot before = mb_page_native_prot(p);
		const uintptr_t maddr = mirror_addr(b, b->addr.start + (idx << MB_PAGESHIFT));
		ensure_committed(b, (size_t)idx, 1);
		/* The baseline copy BEFORE the page is overwritten, as the fault handler
		 * and load_state take it. Taken after, a page this process had never
		 * written - one from a history file, applied to a machine that had not
		 * reached that frame itself - would keep the delta's bytes as its
		 * baseline, and every later return to a frame where the page was clean
		 * would put those bytes back instead of the sealed ones. */
		mb_page_maybe_snapshot(p, maddr);
		if (rd(r, ud, (void *)maddr, MB_PAGESIZE)) return -EIO;
		/* the content is no longer the baseline's, so a full state must carry it */
		set_dirty(b, (size_t)idx, true);
		if (p->hot) memcpy(p->shadow, (const void *)maddr, MB_PAGESIZE);
		if (mb_page_native_prot(p) != before) run_note(b, &run, (size_t)idx);
	}
	run_close(b, &run);

	/* A delta moves the machine, so whatever epoch was open no longer describes
	 * anything. The caller opens the next one when it wants it. Forgetting it
	 * touches only the pages it wrote, and none of them changes protection by
	 * being forgotten: a written page had its hold lifted by the write. */
	mb_block_epoch_clear(b);
	return 0;
}
