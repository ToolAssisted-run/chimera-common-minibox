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
 * it is a guard page (RW|GUARD) when clean and plain RW once dirtied. */
mb_prot mb_page_native_prot(const mb_page *p) {
	if (p->status == MB_ST_FREE) return MB_PROT_NONE;
#ifdef _WIN32
	if (p->status == MB_ST_RWSTACK && p->dirty) return MB_PROT_RW;
#endif
	if (p->status == MB_ST_RW && !p->dirty) return MB_PROT_R;
	if (p->status == MB_ST_RWX && !p->dirty) return MB_PROT_RX;
#ifndef _WIN32
	if (p->status == MB_ST_RWSTACK) return p->dirty ? MB_PROT_RW : MB_PROT_R;
#endif
	return status_prot(p->status);  /* Windows RWStack-clean falls through -> RW|GUARD */
}

void mb_page_maybe_snapshot(mb_page *p, uintptr_t maddr) {
	/* a page nothing has backed yet holds zeros and cannot be read */
	if (p->uncommitted) {
		if (p->snap_kind == MB_SNAP_NONE) p->snap_kind = MB_SNAP_ZERO;
		return;
	}
	if (p->snap_kind == MB_SNAP_NONE) {
		p->snap_data = (uint8_t *)malloc(MB_PAGESIZE);
		memcpy(p->snap_data, (const void *)maddr, MB_PAGESIZE);
		p->snap_kind = MB_SNAP_DATA;
	}
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
	for (size_t i = 0; i < b->npages; i++) free(b->pages[i].snap_data);
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
		i = j;
	}
}

static void refresh_all(mb_block *b) { refresh_range(b, 0, b->npages); }

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

/* apply a uniform status to a page range and refresh */
static void set_protections(mb_block *b, size_t pstart, size_t pcount, uint8_t status) {
	for (size_t i = pstart; i < pstart + pcount; i++) b->pages[i].status = status;
	refresh_range(b, pstart, pcount);
#ifdef _WIN32
	/* On Windows a guard-page (RWStack) write clears the guard bit before we can
	 * observe it, so pre-capture snapshots now while the content is baseline. */
	if (status == MB_ST_RWSTACK)
		for (size_t i = pstart; i < pstart + pcount; i++)
			mb_page_maybe_snapshot(&b->pages[i], mirror_addr(b, b->addr.start + (i << MB_PAGESHIFT)));
#endif
}

/* Windows: recover RWStack dirtiness by scanning cleared guard bits. Must run
 * before any op that changes an RWStack page's status or reads its state. No-op
 * on Linux (RWStack goes through the fault handler). */
static void get_stack_dirty(mb_block *b) {
#ifdef _WIN32
	if (!b->swapped_in) return;
	uintptr_t start = b->addr.start;
	size_t pi = 0;
	while (start < mb_range_end(b->addr)) {
		if (!b->pages[pi].dirty && b->pages[pi].status == MB_ST_RWSTACK) {
			uintptr_t size; bool dirty;
			if (mb_pal_get_stack_dirty(start, &size, &dirty) != 0) { pi++; start += MB_PAGESIZE; continue; }
			while (size > 0 && start < mb_range_end(b->addr)) {
				if (dirty && b->pages[pi].status == MB_ST_RWSTACK) b->pages[pi].dirty = true;
				size -= size < MB_PAGESIZE ? size : MB_PAGESIZE;
				start += MB_PAGESIZE; pi++;
			}
		} else { start += MB_PAGESIZE; pi++; }
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
	get_stack_dirty(b);
	size_t pcount, ps = validate(b, addr, &pcount);
	if (ps == (size_t)-1) return -EINVAL;
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
		if (!b->pages[i].uncommitted) memset((void *)maddr, 0, MB_PAGESIZE);
		/* undirty pages whose sealed baseline was already zero */
		b->pages[i].dirty = !b->pages[i].invisible && b->pages[i].snap_kind != MB_SNAP_ZERO;
	}
	if (advise_only) refresh_range(b, ps, pcount);
	else set_protections(b, ps, pcount, MB_ST_FREE);
}

static int munmap_impl(mb_block *b, mb_range addr, bool advise_only) {
	get_stack_dirty(b);
	size_t pcount, ps = validate(b, addr, &pcount);
	if (ps == (size_t)-1) return -EINVAL;
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
	get_stack_dirty(b);
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
	for (size_t i = ps; i < ps + pcount; i++) { b->pages[i].dirty = true; b->pages[i].invisible = true; }
	refresh_range(b, ps, pcount);
	return 0;
}

int mb_block_copy_from_external(mb_block *b, const uint8_t *src, uintptr_t start, uintptr_t len) {
	mb_range r = { start, len };
	mb_range e = mb_range_align_expand(r);
	size_t pcount, ps = validate(b, e, &pcount);
	if (ps == (size_t)-1) return -EINVAL;
	for (size_t i = ps; i < ps + pcount; i++) b->pages[i].dirty = true;
	ensure_committed(b, ps, pcount);
	memcpy((void *)mirror_addr(b, start), src, len);
	return 0;
}

/* ---- seal ---- */

int mb_block_seal(mb_block *b) {
	if (b->sealed) { fprintf(stderr, "miniBox: already sealed\n"); return -EINVAL; }
	get_stack_dirty(b);
	for (size_t i = 0; i < b->npages; i++) {
		if (b->pages[i].dirty && !b->pages[i].invisible) {
			b->pages[i].dirty = false;
			free(b->pages[i].snap_data);
			b->pages[i].snap_data = NULL;
			b->pages[i].snap_kind = MB_SNAP_NONE; /* live memory is the baseline */
#ifdef _WIN32
			/* guard-page pages need a pre-captured baseline (as in set_protections) */
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

uint8_t mb_block_page_info(const mb_block *b, size_t i) {
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
	uint8_t *flags = (uint8_t *)malloc(b->npages);
	if (!flags) return -ENOMEM;
	for (size_t i = 0; i < b->npages; i++) flags[i] = b->pages[i].status;
	if (wr(w, ud, flags, b->npages)) { free(flags); return -EIO; }
	for (size_t i = 0; i < b->npages; i++) flags[i] = b->pages[i].dirty;
	if (wr(w, ud, flags, b->npages)) { free(flags); return -EIO; }
	free(flags);
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
	char magic[sizeof(MAGIC) - 1];
	if (rd(r, ud, magic, sizeof(magic))) return -EIO;
	if (memcmp(magic, MAGIC, sizeof(magic)) != 0) return -EINVAL;
	uint8_t hash[32];
	if (rd(r, ud, hash, 32)) return -EIO;
	if (memcmp(hash, b->hash, 32) != 0) fprintf(stderr, "miniBox: unexpected MemoryBlock hash mismatch\n");
	mb_range addr;
	if (rd(r, ud, &addr, sizeof(addr))) return -EIO;
	if (addr.start != b->addr.start || addr.size != b->addr.size) return -EINVAL;

	uint8_t *statii = (uint8_t *)malloc(b->npages);
	uint8_t *dirtii = (uint8_t *)malloc(b->npages);
	if (rd(r, ud, statii, b->npages) || rd(r, ud, dirtii, b->npages)) { free(statii); free(dirtii); return -EIO; }

	/* Re-protecting the whole arena after every load is what made a savestate cost
	 * time proportional to the DECLARED layout instead of to what actually
	 * changed: a 272MB layout is 69,632 pages, walked and re-protected per frame
	 * under rewind or a rerecord replay. Only the pages whose protection actually
	 * changes need a syscall, so track those and refresh just their runs. */
	size_t run_start = (size_t)-1, run_end = 0;
	for (size_t i = 0; i < b->npages; i++) {
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
			p->dirty = new_d;
		}
		p->status = statii[i];
		if (mb_page_native_prot(p) != prot_before) {
			if (run_start == (size_t)-1) run_start = i;
			run_end = i;
		} else if (run_start != (size_t)-1) {
			refresh_range(b, run_start, run_end - run_start + 1);
			run_start = (size_t)-1;
		}
	}
	if (run_start != (size_t)-1) refresh_range(b, run_start, run_end - run_start + 1);
	free(statii); free(dirtii);
	return 0;
}
