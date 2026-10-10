/* Tiny test harness shared by the miniBox host unit tests. */
#ifndef MB_TEST_UTIL_H
#define MB_TEST_UTIL_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int mb_test_fails = 0;
static int mb_test_checks = 0;

#define CHECK(c) do { \
	mb_test_checks++; \
	if (!(c)) { fprintf(stderr, "  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); mb_test_fails++; } \
} while (0)

#define CHECK_EQ(a, b) do { \
	mb_test_checks++; \
	long long _a = (long long)(a), _b = (long long)(b); \
	if (_a != _b) { fprintf(stderr, "  FAIL %s:%d  %s == %s  (%lld != %lld)\n", __FILE__, __LINE__, #a, #b, _a, _b); mb_test_fails++; } \
} while (0)

#define RUN(fn) do { fprintf(stderr, "- %s\n", #fn); fn(); } while (0)

#define TEST_MAIN() \
	int main(void) { \
		run_all(); \
		if (mb_test_fails == 0) printf("%s: %d checks passed\n", __FILE__, mb_test_checks); \
		else printf("%s: %d/%d checks FAILED\n", __FILE__, mb_test_fails, mb_test_checks); \
		return mb_test_fails ? 1 : 0; \
	}

/* growable in-memory stream usable as both a reader and a writer callback */
typedef struct { uint8_t *buf; size_t len, cap, pos; } membuf;
static int32_t membuf_write(uintptr_t ud, const uint8_t *data, uintptr_t n) {
	membuf *m = (membuf *)ud;
	if (m->len + n > m->cap) { m->cap = (m->len + n) * 2 + 64; m->buf = realloc(m->buf, m->cap); }
	memcpy(m->buf + m->len, data, n); m->len += n; return 0;
}
static intptr_t membuf_read(uintptr_t ud, uint8_t *data, uintptr_t n) {
	membuf *m = (membuf *)ud;
	uintptr_t avail = m->len - m->pos; if (n > avail) n = avail;
	memcpy(data, m->buf + m->pos, n); m->pos += n; return (intptr_t)n;
}
static void membuf_free(membuf *m) { free(m->buf); m->buf = NULL; m->len = m->cap = m->pos = 0; }

#ifdef MINIBOX_INTERNAL_H
/* The host's page may hold several machine pages (mb_group_pages: 4 on a 16
 * KiB kernel), and a write releases its whole group (memblock.c,
 * group_native_prot): every held page of the host page is recorded as written.
 * These say what a test may expect. With one machine page per host page they
 * are the exact answers a 4 KiB host gives. */
static inline int same_group(size_t a, size_t b) { return a / mb_group_pages() == b / mb_group_pages(); }
/* pages an epoch counts for writes to these pages, every page of each host page
 * being held when it was written */
static inline long written_pages(const size_t *p, size_t n) {
	const size_t g = mb_group_pages();
	long count = 0;
	for (size_t i = 0; i < n; i++) {
		int seen = 0;
		for (size_t j = 0; j < i; j++) if (p[j] / g == p[i] / g) seen = 1;
		if (!seen) count += (long)g;
	}
	return count;
}
#define WRITTEN(...) written_pages((const size_t[]){ __VA_ARGS__ }, \
	sizeof((const size_t[]){ __VA_ARGS__ }) / sizeof(size_t))
#endif

#endif
