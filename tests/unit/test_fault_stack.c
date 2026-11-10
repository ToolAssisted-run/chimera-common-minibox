/* What a write the host tracks leaves on the writer's stack (Chimera issue
 * 555, and the test is the reporter's).
 *
 * Inside one asm block, so rsp does not move and no compiler code runs in
 * between: 16 KB below rsp is filled with a pattern (the 256 bytes just below
 * rsp left alone), one byte is written to a page of a block, and the words of
 * the pattern that changed are counted.
 *
 * A write that faults - a page an epoch holds - leaves Windows' exception
 * frame there (284 words on the reporter's machine, 238 on the GTX 1060 PC):
 * the kernel writes it on the faulting thread's own stack before any handler
 * runs. Linux delivers on the alternate signal stack and leaves it alone. So
 * on Windows only a block that compares writes instead of faulting for them
 * (mb_block_set_compare_writes) leaves the stack as it was - and its write
 * must still be found, by the comparison, in the frame's delta. */
#include "minibox_internal.h"
#include "test_util.h"

#if defined(__x86_64__)

#define FILL_BYTES 16384
/* left alone: the System V red zone, with room to spare */
#define SKIP_BYTES 256
#define FILL_WORDS ((FILL_BYTES - SKIP_BYTES) / 8)

static volatile uint8_t *gp(mb_block *b, uintptr_t off) {
	return (volatile uint8_t *)(b->addr.start + off);
}

/* commit the stack the fill writes: Windows commits a thread's stack through
 * its guard page, and a large frame is probed page by page (___chkstk_ms) */
__attribute__((noinline)) static void commit_stack(void) {
	volatile uint8_t buf[65536];
	for (size_t i = 0; i < sizeof buf; i += 4096) buf[i] = 0;
}

/* fill [rsp - FILL_BYTES, rsp - SKIP_BYTES), write one byte at target, and
 * count the words of the fill that no longer hold the pattern */
__attribute__((noinline)) static uint64_t write_and_count(volatile uint8_t *target) {
	uint64_t changed;
	__asm__ volatile(
		"lea -%c[fill](%%rsp), %%rdi\n\t"
		"mov %[words], %%ecx\n\t"
		"movabs $0x5a17c0de5a17c0de, %%rax\n\t"
		"cld\n\t"
		"rep stosq\n\t"
		"movb $1, (%[t])\n\t"
		"lea -%c[fill](%%rsp), %%rsi\n\t"
		"mov %[words], %%ecx\n\t"
		"xor %[n], %[n]\n"
		"1:\n\t"
		"cmp (%%rsi), %%rax\n\t"
		"je 2f\n\t"
		"inc %[n]\n"
		"2:\n\t"
		"add $8, %%rsi\n\t"
		"dec %%ecx\n\t"
		"jnz 1b\n\t"
		: [n] "=&r"(changed)
		: [t] "r"(target), [fill] "i"(FILL_BYTES), [words] "i"(FILL_WORDS)
		: "rax", "rcx", "rdi", "rsi", "cc", "memory");
	return changed;
}

/* A block of four pages, sealed, every page written once (so dirty and, when
 * faults report writes, writable until an epoch holds it again). One byte
 * written in an epoch: what it left below rsp, and whether the frame's delta
 * has the page. */
static uint64_t one_write(bool compare, bool *found) {
	const uintptr_t size = 4 * MB_PAGESIZE;
	mb_block_set_compare_writes(compare);
	mb_range a = { 0x37000000000ull, size };
	mb_block *b = mb_block_new(a);
	mb_block_set_compare_writes(false);
	mb_block_activate(b);
	mb_range r = { b->addr.start, size };
	CHECK_EQ(mb_block_mmap_fixed(b, r, MB_PROT_RW, true), 0);
	CHECK_EQ(mb_block_seal(b), 0);
	/* 2, so that the 1 written below changes the page: a comparison finds
	 * only a write that changes something */
	for (uintptr_t off = 0; off < size; off += MB_PAGESIZE) gp(b, off)[0] = 2;

	/* control: a write that does not fault changes nothing below rsp */
	commit_stack();
	CHECK_EQ(write_and_count(gp(b, 0)), 0);

	/* one frame described first: a compared page's first delta owes all of
	 * it, having no copy of the frame's start to compare with yet */
	membuf first = { 0 };
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&first), 0);
	free(first.buf);
	/* an epoch holds the pages written: the next write to one faults, unless
	 * the block compares */
	CHECK_EQ(mb_block_epoch_begin(b), 0);
	commit_stack();
	const uint64_t changed = write_and_count(gp(b, MB_PAGESIZE));
	membuf delta = { 0 };
	CHECK_EQ(mb_block_delta_save(b, true, membuf_write, (uintptr_t)&delta), 0);
	*found = mb_block_epoch_page_count(b) == 1;
	free(delta.buf);
	mb_block_free(b);
	return changed;
}

static void test_a_tracked_write_leaves_the_stack_below_rsp_alone(void) {
	bool found = false;
	const uint64_t faulted = one_write(false, &found);
	CHECK(found);
	if (faulted != 0)
		fprintf(stderr, "  a fault changed %llu of %d stack words below rsp\n", (unsigned long long)faulted, FILL_WORDS);
#ifdef _WIN32
	/* Windows: the fault's frame is there; what a core that minds asks for is below */
	CHECK(faulted > 0);
#else
	CHECK_EQ(faulted, 0);
#endif
	found = false;
	const uint64_t compared = one_write(true, &found);
	if (compared != 0)
		fprintf(stderr, "  compared, the write changed %llu of %d stack words below rsp\n", (unsigned long long)compared, FILL_WORDS);
	CHECK_EQ(compared, 0);
	/* and the write is in the frame's delta all the same */
	CHECK(found);
}

static void run_all(void) {
	RUN(test_a_tracked_write_leaves_the_stack_below_rsp_alone);
}

#else
static void run_all(void) { fprintf(stderr, "- skipped: not x86-64\n"); }
#endif

TEST_MAIN()
