/* Memory block: dirty tracking, the mmap/mprotect/munmap/madvise/mremap family,
 * seal, mark_invisible, copy_from_external, and page_info. Exercises the real
 * SIGSEGV fault handler on Linux. */
#include "minibox_internal.h"
#include "test_util.h"
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
	CHECK(!dirty(b, 2));
	CHECK(!dirty(b, 4));
	CHECK_EQ(gp(b, 0x3005)[0], 42);
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
	mb_block_free(b);
}

static void test_mprotect_free_enomem(void) {
	mb_block *b = fresh(0x10000);
	mb_range one = { b->addr.start + 0x2000, 0x1000 };  /* Free */
	CHECK_EQ(mb_block_mprotect(b, one, MB_PROT_RW), -ENOMEM);
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
	mb_block_free(b);
}

static void test_mremap_inplace(void) {
	mb_block *b = fresh(0x10000);
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
	mb_block_free(b);
}

static void test_double_seal(void) {
	mb_block *b = fresh(0x2000);
	CHECK_EQ(mb_block_seal(b), 0);
	CHECK(mb_block_seal(b) != 0);   /* already sealed */
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

	CHECK_EQ(got, 0x5aull);   /* the push and pop actually happened */
	CHECK(dirty(b, 8));       /* and the write is in the state, not lost */
	mb_block_free(b);
}

static void run_all(void) {
	RUN(test_dirty_offset);
	RUN(test_mmap_errors);
	RUN(test_mmap_movable_bestfit);
	RUN(test_mprotect_free_enomem);
	RUN(test_munmap_zeroes);
	RUN(test_madvise_keeps_allocated);
	RUN(test_mremap_inplace);
	RUN(test_invisible);
	RUN(test_double_seal);
	RUN(test_copy_from_external);
	RUN(test_page_info_encoding);
	RUN(test_write_with_sp_in_a_declared_stack);
}
TEST_MAIN()
