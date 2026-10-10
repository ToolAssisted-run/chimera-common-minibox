/* Memory block: dirty tracking, the mmap/mprotect/munmap/madvise/mremap family,
 * seal, mark_invisible, copy_from_external, and page_info. Exercises the real
 * SIGSEGV fault handler on Linux. */
#include "minibox_internal.h"
#include "test_util.h"
#ifndef _WIN32
#include <sys/mman.h>
#else
#include <windows.h>
#endif
#include <errno.h>

/* helpers */
static uint8_t pi(mb_block *b, size_t i) { return mb_block_page_info(b, i); }
static bool dirty(mb_block *b, size_t i) { return pi(b, i) & 0x80; }
static bool invis(mb_block *b, size_t i) { return pi(b, i) & 0x40; }
static bool freed(mb_block *b, size_t i) { return (pi(b, i) & 0x3f) == 0; }
static volatile uint8_t *gp(mb_block *b, uintptr_t off) { return (volatile uint8_t *)(b->addr.start + off); }

static mb_block *fresh(uintptr_t size) {
	mb_range a = { 0x36f00000000ull, size };
	mb_block *b = mb_block_new(a);
	mb_block_activate(b);
	return b;
}

static void test_dirty_offset(void) {
	mb_block *b = fresh(0x20000);
	mb_range r = { b->addr.start, 0x20000 };
	CHECK_EQ(mb_block_mmap_fixed(b, r, MB_PROT_RW, true), 0);
	CHECK(!dirty(b, 3));
	gp(b, 0x3005)[0] = 42;         /* write into page 3 */
	CHECK(dirty(b, 3));
	CHECK_EQ(dirty(b, 2), same_group(2, 3));   /* only its host page's neighbours */
	CHECK_EQ(dirty(b, 4), same_group(4, 3));
	CHECK_EQ(gp(b, 0x3005)[0], 42);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

static void test_mmap_errors(void) {
	mb_block *b = fresh(0x10000);
	mb_range whole = { b->addr.start, 0x10000 };
	CHECK_EQ(mb_block_mmap_fixed(b, whole, MB_PROT_RW, true), 0);
	/* no_replace over an allocated page -> EEXIST */
	mb_range one = { b->addr.start + 0x2000, 0x1000 };
	CHECK_EQ(mb_block_mmap_fixed(b, one, MB_PROT_RW, true), -EEXIST);
	/* size 0 -> EINVAL */
	mb_range z = { b->addr.start, 0 };
	CHECK_EQ(mb_block_mmap_fixed(b, z, MB_PROT_RW, true), -EINVAL);
	/* out of range -> EINVAL */
	mb_range oor = { b->addr.start + 0x10000, 0x1000 };
	CHECK_EQ(mb_block_mmap_fixed(b, oor, MB_PROT_RW, true), -EINVAL);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

static void test_mmap_movable_bestfit(void) {
	mb_block *b = fresh(0x10000);   /* 16 pages */
	/* carve a 2-page hole and a 4-page hole; best-fit picks the smallest that fits */
	mb_range all = { b->addr.start, 0x10000 };
	CHECK_EQ(mb_block_mmap_fixed(b, all, MB_PROT_RW, true), 0);
	mb_range h2 = { b->addr.start + 0x1000, 0x2000 };
	mb_range h4 = { b->addr.start + 0x6000, 0x4000 };
	CHECK_EQ(mb_block_munmap(b, h2), 0);
	CHECK_EQ(mb_block_munmap(b, h4), 0);
	mb_range req = { 0, 0x2000 };   /* want 2 pages -> should land in the 2-page hole */
	mb_sword got = mb_block_mmap(b, req, MB_PROT_RW, all, false);
	CHECK_EQ(got, (mb_sword)(b->addr.start + 0x1000));
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

static void test_mprotect_free_enomem(void) {
	mb_block *b = fresh(0x10000);
	mb_range one = { b->addr.start + 0x2000, 0x1000 };  /* Free */
	CHECK_EQ(mb_block_mprotect(b, one, MB_PROT_RW), -ENOMEM);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

static void test_munmap_zeroes(void) {
	mb_block *b = fresh(0x10000);
	mb_range whole = { b->addr.start, 0x10000 };
	CHECK_EQ(mb_block_mmap_fixed(b, whole, MB_PROT_RW, true), 0);
	gp(b, 0x5000)[0] = 7;
	mb_range one = { b->addr.start + 0x5000, 0x1000 };
	CHECK_EQ(mb_block_munmap(b, one), 0);
	CHECK(freed(b, 5));
	/* re-map and confirm it reads back zero (munmap zeroed it) */
	CHECK_EQ(mb_block_mmap_fixed(b, one, MB_PROT_RW, false), 0);
	CHECK_EQ(gp(b, 0x5000)[0], 0);
	/* munmap of a Free page -> EINVAL (free it once, then again) */
	mb_range fr = { b->addr.start + 0x9000, 0x1000 };
	CHECK_EQ(mb_block_munmap(b, fr), 0);
	CHECK_EQ(mb_block_munmap(b, fr), -EINVAL);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

static void test_madvise_keeps_allocated(void) {
	mb_block *b = fresh(0x10000);
	mb_range whole = { b->addr.start, 0x10000 };
	CHECK_EQ(mb_block_mmap_fixed(b, whole, MB_PROT_RW, true), 0);
	gp(b, 0x4000)[0] = 9;
	mb_range one = { b->addr.start + 0x4000, 0x1000 };
	CHECK_EQ(mb_block_madvise_dontneed(b, one), 0);
	CHECK(!freed(b, 4));            /* still allocated... */
	CHECK_EQ(gp(b, 0x4000)[0], 0);  /* ...but zeroed */
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

static void test_mremap_maymove(void) {
	mb_block *b = fresh(0x10000);
	mb_range arena = { b->addr.start, 0x10000 };
	mb_range two = { b->addr.start, 0x2000 };
	CHECK_EQ(mb_block_mmap_fixed(b, two, MB_PROT_RW, true), 0);
	gp(b, 0)[0] = 0xAB; gp(b, 0x1000)[0] = 0xCD;
	/* block the in-place grow */
	mb_range blocker = { b->addr.start + 0x2000, 0x1000 };
	CHECK_EQ(mb_block_mmap_fixed(b, blocker, MB_PROT_RW, true), 0);
	/* without maymove: EEXIST, as in v2 */
	CHECK_EQ(mb_block_mremap_maymove(b, two, 0x4000, arena, false), -EEXIST);
	/* with maymove: relocates, contents follow, old range is free */
	mb_sword moved = mb_block_mremap_maymove(b, two, 0x4000, arena, true);
	CHECK(moved > 0 && moved != (mb_sword)b->addr.start);
	CHECK_EQ(gp(b, (uintptr_t)(moved - (mb_sword)b->addr.start))[0], 0xAB);
	CHECK_EQ(gp(b, (uintptr_t)(moved - (mb_sword)b->addr.start) + 0x1000)[0], 0xCD);
	CHECK(freed(b, 0) && freed(b, 1));
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

static void test_range_is_free(void) {
	mb_block *b = fresh(0x10000);
	mb_range two = { b->addr.start, 0x2000 };
	CHECK(mb_block_range_is_free(b, two));
	CHECK_EQ(mb_block_mmap_fixed(b, two, MB_PROT_RW, true), 0);
	CHECK(!mb_block_range_is_free(b, two));
	mb_range half = { b->addr.start + 0x1000, 0x2000 };
	CHECK(!mb_block_range_is_free(b, half));   /* overlaps */
	mb_range oor = { b->addr.start + 0x10000, 0x1000 };
	CHECK(!mb_block_range_is_free(b, oor));    /* outside */
	mb_block_free(b);
}

static void test_mremap_inplace(void) {	mb_block *b = fresh(0x10000);
	mb_range two = { b->addr.start, 0x2000 };
	CHECK_EQ(mb_block_mmap_fixed(b, two, MB_PROT_RW, true), 0);
	/* grow in place: following pages are free -> ok */
	mb_sword g = mb_block_mremap(b, two, 0x4000, (mb_range){0,0});
	CHECK_EQ(g, (mb_sword)b->addr.start);
	CHECK(!freed(b, 3));
	/* grow blocked: allocate the page after, then try to grow over it -> EEXIST */
	mb_range four = { b->addr.start, 0x4000 };
	mb_range blocker = { b->addr.start + 0x5000, 0x1000 };
	CHECK_EQ(mb_block_mmap_fixed(b, blocker, MB_PROT_RW, true), 0);
	CHECK_EQ(mb_block_mremap(b, four, 0x6000, (mb_range){0,0}), -EEXIST);
	/* shrink: tail becomes free */
	CHECK_EQ(mb_block_mremap(b, four, 0x2000, (mb_range){0,0}), (mb_sword)b->addr.start);
	CHECK(freed(b, 3));
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

static void test_invisible(void) {
	mb_block *b = fresh(0x10000);
	mb_range one = { b->addr.start + 0x7000, 0x1000 };
	CHECK_EQ(mb_block_mark_invisible(b, one), 0);
	CHECK(invis(b, 7));
	mb_block_seal(b);
	/* mark_invisible after seal -> error */
	mb_range two = { b->addr.start + 0x8000, 0x1000 };
	CHECK(mb_block_mark_invisible(b, two) != 0);
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

static void test_double_seal(void) {
	mb_block *b = fresh(0x2000);
	CHECK_EQ(mb_block_seal(b), 0);
	CHECK(mb_block_seal(b) != 0);   /* already sealed */
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

static void test_copy_from_external(void) {
	mb_block *b = fresh(0x10000);
	mb_range whole = { b->addr.start, 0x10000 };
	CHECK_EQ(mb_block_mmap_fixed(b, whole, MB_PROT_RW, true), 0);
	uint8_t src[100];
	for (int i = 0; i < 100; i++) src[i] = (uint8_t)(i * 3 + 1);
	CHECK_EQ(mb_block_copy_from_external(b, src, b->addr.start + 0x1234, 100), 0);
	for (int i = 0; i < 100; i++) CHECK_EQ(gp(b, 0x1234 + i)[0], (uint8_t)(i*3+1));
	CHECK(dirty(b, 1));  /* the touched page is dirty */
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

static void test_page_info_encoding(void) {
	mb_block *b = fresh(0x8000);
	mb_range r = { b->addr.start, 0x1000 };
	CHECK_EQ(mb_block_mmap_fixed(b, r, MB_PROT_RX, true), 0);
	CHECK_EQ(pi(b, 0) & 0x3f, 0x05);   /* RX */
	mb_range r2 = { b->addr.start + 0x1000, 0x1000 };
	CHECK_EQ(mb_block_mmap_fixed(b, r2, MB_PROT_R, true), 0);
	CHECK_EQ(pi(b, 1) & 0x3f, 0x01);   /* R */
	CHECK_EQ(pi(b, 7) & 0x3f, 0x00);   /* Free */
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* A guest that runs on a stack it declared.
 *
 * This is the shape that killed the ares core on Windows and nothing else: a
 * coroutine library (libco, one stack per emulated component) hands out stacks,
 * and the first push onto a freshly sealed one is a write fault on the page the
 * stack pointer is IN.
 *
 * On Windows an exception is delivered by pushing a context record onto the
 * faulting thread's own stack. If that page is merely read-only the kernel's
 * write fails too, no handler runs, nothing is logged, and the process dies
 * with an access violation. So on Windows a stack is never protected and never
 * clean - it is written to a savestate whether or not anybody touched it. That
 * is the whole reason MB_PROT_RWSTACK exists, and why a guest has to ask for a
 * stack with MAP_STACK rather than use whatever memory it happens to have; see
 * mb_page_native_prot. Linux takes the ordinary fault and needs none of it. */
static void test_write_with_sp_in_a_declared_stack(void) {
	mb_block *b = fresh(0x10000);
	mb_range r = { b->addr.start, 0x10000 };
	CHECK_EQ(mb_block_mmap_fixed(b, r, MB_PROT_RW, true), 0);
	mb_range stack = { b->addr.start + 0x8000, 0x1000 };
	CHECK_EQ(mb_block_mprotect(b, stack, MB_PROT_RWSTACK), 0);

	/* Everything below the stack page is already dirty, so the only page that
	 * can fault is the one holding the stack pointer - which is the case being
	 * tested, and keeps a faulting handler off a second clean page. */
	for (size_t i = 0; i < 8; i++) gp(b, (i << 12) + 8)[0] = (uint8_t)i;

	/* Put the stack pointer near the top of the stack page and write through it. */
	volatile uint8_t *sp = gp(b, 0x9000 - 64);
	uint64_t got = 0;
#if defined(__aarch64__)
	__asm__ __volatile__(
		"mov x11, sp\n\t"
		"mov sp, %1\n\t"
		"mov x12, #0x5a\n\t"
		"str x12, [sp, #-16]!\n\t"
		"ldr %0, [sp], #16\n\t"
		"mov sp, x11\n\t"
		: "=&r"(got)
		: "r"(sp)
		: "x11", "x12", "memory", "cc");
#elif defined(__x86_64__)
	__asm__ __volatile__(
		"mov %%rsp, %%r11\n\t"
		"mov %1, %%rsp\n\t"
		"pushq $0x5a\n\t"
		"popq %%rax\n\t"
		"mov %%r11, %%rsp\n\t"
		"mov %%rax, %0\n\t"
		: "=r"(got)
		: "r"(sp)
		: "r11", "rax", "memory", "cc");
#else
#error "miniBox runs on x86-64 and aarch64 only"
#endif

	CHECK_EQ(got, 0x5aull);   /* the push and pop actually happened */
	CHECK(dirty(b, 8));       /* and the write is in the state, not lost */
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* A freed block gives its memory back - the MIRROR view included.
 *
 * The mirror is a view of the block's section, and it was released the way an
 * anonymous mapping is. On Windows that call cannot release a view and failed
 * silently, so every freed block left its whole mirror mapped; a frontend that
 * rebooted a core a few dozen times could no longer create a block at all. */
static void test_free_releases_the_mirror(void) {
	for (int round = 0; round < 3; round++) {
		mb_range a = { 0x36f00000000ull, 0x100000 };
		mb_block *b = mb_block_new(a);
		CHECK(b != NULL);
		if (!b) return;
		uintptr_t mirror = b->mirror.start;
		size_t size = b->mirror.size;
		mb_block_activate(b);
		mb_block_free(b);
#ifdef _WIN32
		MEMORY_BASIC_INFORMATION mbi;
		CHECK_EQ(VirtualQuery((void *)mirror, &mbi, sizeof mbi), sizeof mbi);
		CHECK_EQ(mbi.State, (DWORD)MEM_FREE);
#else
		/* msync answers ENOMEM for a range that is not mapped */
		errno = 0;
		CHECK_EQ(msync((void *)mirror, size, MS_ASYNC), -1);
		CHECK_EQ(errno, ENOMEM);
#endif
		(void)size;
	}
}

#ifdef _WIN32
/* chimera#166: a commit the system refuses (out of memory) leaves the pages
 * uncommitted instead of claiming them, and the guest's first touch of one
 * commits it then - the write lands, and is tracked, as any other. It used to
 * mark them committed anyway, so the touch faulted as "the core crashed" and
 * nothing ever tried again. */
/* Wine says so in ntdll; Windows has no such export. */
static bool under_wine(void) {
	HMODULE nt = GetModuleHandleA("ntdll.dll");
	return nt != NULL && GetProcAddress(nt, "wine_get_version") != NULL;
}

/* only a block over 4 GiB is lazy (pal_win.c): reserved, not committed */
#define LAZY_SIZE (((uintptr_t)4 << 30) + 0x20000)

static void test_refused_commit_is_retried_on_fault(void) {
	mb_block *b = fresh(LAZY_SIZE);
	CHECK(b->handle.lazy);
	mb_range r = { b->addr.start, 0x4000 };
	mb_pal_commit_refusals = 1;                 /* the mmap's commit is refused */
	CHECK_EQ(mb_block_mmap_fixed(b, r, MB_PROT_RW, true), 0);
	CHECK_EQ(mb_pal_commit_refusals, 0);
	CHECK(b->pages[0].uncommitted);             /* not claimed */
	gp(b, 0x10)[0] = 7;                         /* faults, is committed, lands */
	CHECK_EQ(gp(b, 0x10)[0], 7);
	CHECK(!b->pages[0].uncommitted);
	CHECK(dirty(b, 0));
	CHECK(!dirty(b, 1));
	gp(b, 0x2010)[0] = 9;                       /* another refused page, the same way */
	CHECK_EQ(gp(b, 0x2010)[0], 9);
	CHECK(dirty(b, 2));
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* A v3 mremap that moves (MREMAP_MAYMOVE) commits the new range and then the
 * HOST copies the old pages into it. Refused, that commit leaves the pages
 * uncommitted on purpose, and a copy into them is a host fault, not a guest
 * access the fault path would serve: the move must stop with ENOMEM, the old
 * mapping as it was and the new range still free. */
static void test_refused_commit_stops_a_move(void) {
	mb_block *b = fresh(LAZY_SIZE);
	CHECK(b->handle.lazy);
	mb_range arena = { b->addr.start, 0x40000 };
	mb_range two = { b->addr.start, 0x2000 };
	CHECK_EQ(mb_block_mmap_fixed(b, two, MB_PROT_RW, true), 0);
	gp(b, 0)[0] = 0xAB; gp(b, 0x1000)[0] = 0xCD;
	mb_range blocker = { b->addr.start + 0x2000, 0x1000 };   /* no growing in place */
	CHECK_EQ(mb_block_mmap_fixed(b, blocker, MB_PROT_RW, true), 0);
	mb_pal_commit_refusals = 1;                 /* the move's commit is refused */
	CHECK_EQ(mb_block_mremap_maymove(b, two, 0x4000, arena, true), -ENOMEM);
	CHECK_EQ(mb_pal_commit_refusals, 0);
	CHECK_EQ(gp(b, 0)[0], 0xAB);                /* the old mapping, untouched */
	CHECK_EQ(gp(b, 0x1000)[0], 0xCD);
	mb_range after = { b->addr.start + 0x3000, 0x4000 };
	CHECK(mb_block_range_is_free(b, after));     /* nothing claimed for the move */
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

/* Refused again on the fault: the host is out of memory, which the fault
 * handler reports as that; with memory back, the same page is served. */
static void test_refused_again_is_out_of_memory(void) {
	mb_block *b = fresh(LAZY_SIZE);
	mb_range r = { b->addr.start, 0x4000 };
	mb_pal_commit_refusals = 1;
	CHECK_EQ(mb_block_mmap_fixed(b, r, MB_PROT_RW, true), 0);
	mb_pal_commit_refusals = 1;
	bool oom = false;
	CHECK(!mb_block_commit_on_fault(b, b->addr.start + 0x10, true, &oom));
	CHECK(oom);
	CHECK(b->pages[0].uncommitted);
	oom = false;
	CHECK(mb_block_commit_on_fault(b, b->addr.start + 0x10, true, &oom));
	CHECK(!oom);
	CHECK(!b->pages[0].uncommitted);
	/* a page the guest may not write is not this handler's to serve */
	CHECK(!mb_block_commit_on_fault(b, b->addr.start + 0x8000, true, &oom));
	CHECK(!oom);
	mb_block_free(b);
}
#endif

/* Where a movable mmap lands, found the slow way: the page-by-page walk
 * find_free_pages did before it kept group_free (the top-down highest fit for
 * a big request, best fit from the bottom otherwise). The fast walk must give
 * this answer every time - a guest's addresses are part of its machine. */
static size_t reference_place(mb_block *b, size_t npages) {
	const size_t end = b->npages;
	if (npages >= 4096) {
		size_t i = end, run_end = end;
		while (i > 0) {
			i--;
			if (b->status_map[i] != MB_ST_FREE) { run_end = i; continue; }
			if (run_end - i >= npages) return run_end - npages;
		}
		return (size_t)-1;
	}
	size_t best = (size_t)-1, best_len = (size_t)-1, i = 0;
	while (i < end) {
		if (b->status_map[i] == MB_ST_FREE) {
			size_t j = i;
			while (j < end && b->status_map[j] == MB_ST_FREE) j++;
			if (j - i >= npages && j - i < best_len) { best = i; best_len = j - i; }
			i = j;
		} else i++;
	}
	return best;
}

static bool group_counts_right(mb_block *b) {
	for (size_t g = 0; g * MB_GROUP_PAGES < b->npages; g++) {
		uint32_t n = 0;
		for (size_t i = g * MB_GROUP_PAGES; i < (g + 1) * MB_GROUP_PAGES && i < b->npages; i++)
			n += b->status_map[i] == MB_ST_FREE;
		if (n != b->group_free[g]) return false;
	}
	return true;
}

/* Thousands of movable mmaps and munmaps, big and small, over a block with
 * whole groups taken, whole groups free and groups in pieces (and a size
 * that is not a whole number of groups): every placement must be the
 * reference walk's, and the per-group counts must match a recount. */
static void test_mmap_placement_is_the_page_walks(void) {
	const uintptr_t size = (uintptr_t)(19 * MB_GROUP_PAGES + 77) << MB_PAGESHIFT;
	mb_block *b = fresh(size);
	mb_range arena = { b->addr.start, size };
	struct { uintptr_t at; size_t pages; } live[256];
	int nlive = 0, placed = 0, refused = 0, mismatches = 0;
	uint32_t seed = 12345;
#define NEXT() (seed = seed * 1103515245u + 12345u, (seed >> 8))
	for (int step = 0; step < 20000; step++) {
		const uint32_t what = NEXT() % 6;
		if (nlive > 0 && (nlive == 256 || what < 2)) {
			const int k = (int)(NEXT() % (uint32_t)nlive);
			mb_range r = { live[k].at, live[k].pages << MB_PAGESHIFT };
			CHECK_EQ(mb_block_munmap(b, r), 0);
			live[k] = live[--nlive];
		} else if (what == 2) {
			/* a single page pinned at a random free place: groups with one
			 * page taken, or one page free, are where a wrong shortcut shows */
			const size_t at = NEXT() % b->npages;
			if (b->status_map[at] == MB_ST_FREE) {
				mb_range r = { b->addr.start + (at << MB_PAGESHIFT), (uintptr_t)1 << MB_PAGESHIFT };
				CHECK_EQ(mb_block_mmap_fixed(b, r, MB_PROT_RW, true), 0);
				live[nlive].at = r.start;
				live[nlive].pages = 1;
				nlive++;
			}
		} else {
			const uint32_t pick = NEXT() % 100;
			const size_t npages = pick < 5 ? 4096 + NEXT() % 3000   /* big: from the top */
				: pick < 15 ? MB_GROUP_PAGES * (1 + NEXT() % 3)     /* whole groups */
				: 1 + NEXT() % 700;                                 /* small */
			const size_t want = reference_place(b, npages);
			mb_range r = { 0, npages << MB_PAGESHIFT };
			const mb_sword got = mb_block_mmap(b, r, MB_PROT_RW, arena, false);
			if (want == (size_t)-1) {
				CHECK(got < 0);
				refused++;
			} else {
				if (got != (mb_sword)(b->addr.start + (want << MB_PAGESHIFT))) mismatches++;
				if (got >= 0) { live[nlive].at = (uintptr_t)got; live[nlive].pages = npages; nlive++; placed++; }
			}
		}
		if (!group_counts_right(b)) { CHECK(group_counts_right(b)); break; }
	}
#undef NEXT
	fprintf(stderr, "  %d placed, %d refused for want of room, %d mismatches\n", placed, refused, mismatches);
	CHECK_EQ(mismatches, 0);
	CHECK(placed > 500);
	CHECK(refused > 50);  /* the full-arena path was walked too */
	CHECK(mb_block_maps_consistent(b));
	mb_block_free(b);
}

static void run_all(void) {
	test_free_releases_the_mirror();
	RUN(test_dirty_offset);
	RUN(test_mmap_errors);
	RUN(test_mmap_movable_bestfit);
	RUN(test_mmap_placement_is_the_page_walks);
	RUN(test_mprotect_free_enomem);
	RUN(test_munmap_zeroes);
	RUN(test_madvise_keeps_allocated);
	RUN(test_mremap_inplace);
	RUN(test_mremap_maymove);
	RUN(test_range_is_free);
	RUN(test_invisible);
	RUN(test_double_seal);
	RUN(test_copy_from_external);
	RUN(test_page_info_encoding);
	RUN(test_write_with_sp_in_a_declared_stack);
#ifdef _WIN32
	/* Real Windows only. Wine reimplements Win32 and will not commit pages
	 * inside a reserved section's view: the retry these two make at fault
	 * time gets VirtualAlloc(MEM_COMMIT) error 1455 on the CI runner, so they
	 * failed there from the day they were written while passing on Windows.
	 * The windows-latest job runs them; under wine they are said, not run. */
	if (under_wine()) {
		fprintf(stderr, "- SKIP under wine: test_refused_commit_is_retried_on_fault, test_refused_again_is_out_of_memory (wine cannot commit in a reserved view; the native Windows job runs them)\n");
	} else {
		RUN(test_refused_commit_is_retried_on_fault);
		RUN(test_refused_again_is_out_of_memory);
		RUN(test_refused_commit_stops_a_move);
	}
#endif
}
TEST_MAIN()
