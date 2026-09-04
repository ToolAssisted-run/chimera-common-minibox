/* Guest green threads: cooperative, host-scheduled, one running at a time.
 * A guest pthread is created by the custom NR_WBX_CLONE syscall; a context
 * switch is just swapping Context.guest_rsp + thread_area. Faithful C port of
 * BizHawk waterboxhost src/threading.rs (single-host, phase 2). */
#include "minibox_internal.h"
#include "minibox_threads.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Set MB_TDBG=1 to trace thread ops (spawn/exit/futex) - off by default. */
static int mb_tdbg(void) { static int v = -1; if (v < 0) { const char *e = getenv("MB_TDBG"); v = e && *e ? 1 : 0; } return v; }
#define TDBG(...) do { if (mb_tdbg()) fprintf(stderr, "[T] " __VA_ARGS__); } while (0)

#define FUTEX_WAITERS 0x80000000u

static uintptr_t sok(mb_sword v) { return (uintptr_t)v; }
static uintptr_t serr(int e) { return (uintptr_t)(intptr_t)(-e); }

typedef enum { T_RUNNABLE, T_WAITING } tstate;
typedef struct {
	uint32_t tid;
	tstate state;
	uintptr_t rax;         /* return value handed to the guest when next run */
	uintptr_t rsp;         /* guest_rsp when next run */
	uintptr_t thread_area; /* pthread_self */
	uintptr_t tid_address; /* set_tid_address */
	mb_range stack;        /* this thread's own stack, from its pthread struct */
	mb_range pending;      /* a munmap of that stack, held until it has left it */
} gthread;

typedef struct { uintptr_t addr; uint32_t *tids; size_t n, cap; } futex_queue;

struct mb_threads {
	uint32_t next_tid;
	uint32_t active_tid;
	gthread *threads; size_t nthreads, cap;   /* kept sorted by tid ascending */
	futex_queue *futicies; size_t nfut, futcap;
};

/* ---- thread array (sorted by tid) ---- */
static gthread *find_thread(mb_threads *t, uint32_t tid) {
	for (size_t i = 0; i < t->nthreads; i++) if (t->threads[i].tid == tid) return &t->threads[i];
	return NULL;
}
static void insert_thread(mb_threads *t, gthread g) {
	if (t->nthreads == t->cap) { t->cap = t->cap ? t->cap * 2 : 8; t->threads = realloc(t->threads, t->cap * sizeof(gthread)); }
	size_t i = t->nthreads;
	while (i > 0 && t->threads[i-1].tid > g.tid) { t->threads[i] = t->threads[i-1]; i--; }
	t->threads[i] = g; t->nthreads++;
}
static void remove_thread(mb_threads *t, uint32_t tid) {
	for (size_t i = 0; i < t->nthreads; i++)
		if (t->threads[i].tid == tid) { memmove(&t->threads[i], &t->threads[i+1], (t->nthreads-i-1)*sizeof(gthread)); t->nthreads--; return; }
}

/* ---- futex queues ---- */
static futex_queue *find_queue(mb_threads *t, uintptr_t addr) {
	for (size_t i = 0; i < t->nfut; i++) if (t->futicies[i].addr == addr) return &t->futicies[i];
	return NULL;
}
static futex_queue *get_or_make_queue(mb_threads *t, uintptr_t addr) {
	futex_queue *q = find_queue(t, addr);
	if (q) return q;
	if (t->nfut == t->futcap) { t->futcap = t->futcap ? t->futcap*2 : 4; t->futicies = realloc(t->futicies, t->futcap*sizeof(futex_queue)); }
	q = &t->futicies[t->nfut++];
	q->addr = addr; q->tids = NULL; q->n = 0; q->cap = 0;
	return q;
}
static void queue_push(futex_queue *q, uint32_t tid) {
	if (q->n == q->cap) { q->cap = q->cap ? q->cap*2 : 4; q->tids = realloc(q->tids, q->cap*sizeof(uint32_t)); }
	q->tids[q->n++] = tid;
}
static void remove_queue(mb_threads *t, uintptr_t addr) {
	for (size_t i = 0; i < t->nfut; i++)
		if (t->futicies[i].addr == addr) { free(t->futicies[i].tids); memmove(&t->futicies[i], &t->futicies[i+1], (t->nfut-i-1)*sizeof(futex_queue)); t->nfut--; return; }
}

/* returns tid unparked (and whether more remain), or -1 */
static int unpark_one(mb_threads *t, uintptr_t addr, uint32_t *out_tid, bool *has_more) {
	futex_queue *q = find_queue(t, addr);
	if (!q || q->n == 0) return -1;
	uint32_t tid = q->tids[0];
	memmove(&q->tids[0], &q->tids[1], (q->n-1)*sizeof(uint32_t)); q->n--;
	gthread *g = find_thread(t, tid); if (g) g->state = T_RUNNABLE;
	*out_tid = tid;
	if (q->n == 0) { remove_queue(t, addr); *has_more = false; } else *has_more = true;
	return 0;
}

/* ---- lifecycle ---- */
mb_threads *mb_threads_new(void) {
	mb_threads *t = calloc(1, sizeof(mb_threads));
	t->next_tid = 2;
	t->active_tid = 1;
	gthread main_thread = { 1, T_RUNNABLE, sok(0), 0, 0, 0 };
	insert_thread(t, main_thread);
	return t;
}
void mb_threads_free(mb_threads *t) {
	if (!t) return;
	for (size_t i = 0; i < t->nfut; i++) free(t->futicies[i].tids);
	free(t->futicies); free(t->threads); free(t);
}

/* ---- scheduling ---- */
static uintptr_t swap_to(mb_threads *t, mb_context *c, uint32_t tid, uintptr_t ret) {
	gthread *old = find_thread(t, t->active_tid);
	old->rax = ret; old->rsp = c->guest_rsp; old->thread_area = c->thread_area;
	gthread *nw = find_thread(t, tid);
	c->guest_rsp = nw->rsp; c->thread_area = nw->thread_area;
	t->active_tid = tid;
	return nw->rax;
}

/* next runnable tid in ascending order wrapping around active */
static uintptr_t swap_to_next(mb_threads *t, mb_context *c, uintptr_t ret) {
	uint32_t best = 0; bool found = false;
	/* first strictly-greater tid, then wrap to smallest */
	for (size_t i = 0; i < t->nthreads; i++)
		if (t->threads[i].tid > t->active_tid && t->threads[i].state == T_RUNNABLE) { best = t->threads[i].tid; found = true; break; }
	if (!found)
		for (size_t i = 0; i < t->nthreads; i++)
			if (t->threads[i].state == T_RUNNABLE) { best = t->threads[i].tid; found = true; break; }
	if (!found) { fprintf(stderr, "miniBox: all threads fell asleep. states:"); for (size_t i=0;i<t->nthreads;i++) fprintf(stderr, " t%u=%s", t->threads[i].tid, t->threads[i].state==T_RUNNABLE?"R":"W"); fprintf(stderr, "\n"); __builtin_trap(); return ret; }
	if (best == t->active_tid) return ret;   /* yield that didn't change thread */
	return swap_to(t, c, best, ret);
}

static uintptr_t park_me(mb_threads *t, mb_context *c, uintptr_t ret, uintptr_t addr) {
	queue_push(get_or_make_queue(t, addr), t->active_tid);
	find_thread(t, t->active_tid)->state = T_WAITING;
	return swap_to_next(t, c, ret);
}
static void park_other(mb_threads *t, uintptr_t addr, uint32_t tid) {
	queue_push(get_or_make_queue(t, addr), tid);
	find_thread(t, tid)->state = T_WAITING;
}

/* ---- syscalls ---- */
mb_sword mb_threads_spawn(mb_threads *t, mb_block *b, uintptr_t thread_area,
                      uintptr_t guest_rsp, uintptr_t guest_rip, uintptr_t child_tid, uint32_t *parent_tid) {
	uint32_t tid = t->next_tid;
	/* the musl pthread struct: words 12,13 are stack_end and stack_size */
	const uintptr_t *pthread = (const uintptr_t *)thread_area;
	uintptr_t stack_end = pthread[12], stack_size = pthread[13];
	mb_range stack = { stack_end - stack_size, stack_size };
	int rc = mb_block_mprotect(b, mb_range_align_expand(stack), MB_PROT_RWSTACK);
	if (rc != 0) return rc;
	/* set up the child's initial frame so guest_syscall's `pop rbp; ret` lands at guest_rip */
	uintptr_t *child_stack = (uintptr_t *)(guest_rsp - 16);
	child_stack[0] = 0;          /* rbp */
	child_stack[1] = guest_rip;  /* ret target */
	*parent_tid = tid;
	gthread g = { tid, T_RUNNABLE, sok(0), guest_rsp - 16, thread_area, child_tid, stack, { 0, 0 } };
	insert_thread(t, g);
	t->next_tid++;
	TDBG("spawn tid=%u rip=%lx rsp=%lx\n",tid,(unsigned long)guest_rip,(unsigned long)(guest_rsp-16));
	return (mb_sword)tid;
}

uintptr_t mb_threads_exit(mb_threads *t, mb_context *c) {
	if (t->active_tid == 1) { __builtin_trap(); }
	gthread *self = find_thread(t, t->active_tid);
	uintptr_t addr = self->tid_address;
	if (addr != 0) { *(uint32_t *)addr = 0; uint32_t tid; bool more; unpark_one(t, addr, &tid, &more); }
	TDBG("exit tid=%u\n",t->active_tid);
	uint32_t dead = t->active_tid;
	uintptr_t ret = swap_to_next(t, c, sok(0));
	if (t->active_tid == dead) { fprintf(stderr, "miniBox: last thread exited\n"); __builtin_trap(); }
	remove_thread(t, dead);
	return ret;
}

/* A thread that is ending unmaps its OWN stack and then exits - musl's
 * __unmapself, which on real Linux is asm that touches no stack between the two
 * syscalls. Here a syscall is a call OUT of the box that has to RETURN, onto
 * exactly the stack just freed. So hold the unmap: take it at exit, once the
 * thread has been swapped off that stack for good. Without this the return path
 * reads a freed page and the box takes the fault.
 * Returns true when the range was taken over and must not be unmapped now. */
bool mb_threads_hold_stack_unmap(mb_threads *t, mb_range r) {
	gthread *self = find_thread(t, t->active_tid);
	if (self == NULL || self->stack.size == 0) return false;
	const uintptr_t rs = r.start, re = r.start + r.size;
	const uintptr_t ss = self->stack.start, se = self->stack.start + self->stack.size;
	if (rs >= se || re <= ss) return false;   /* nothing to do with this thread's stack */
	self->pending = r;
	TDBG("hold stack unmap tid=%u addr=%lx size=%lx\n",
		t->active_tid,(unsigned long)r.start,(unsigned long)r.size);
	return true;
}

/* The unmap held above, to be done by the caller once mb_threads_exit returns
 * - by then the dead thread is off its stack and another one is running. */
bool mb_threads_take_held_unmap(mb_threads *t, mb_range *out) {
	gthread *self = find_thread(t, t->active_tid);
	if (self == NULL || self->pending.size == 0) return false;
	*out = self->pending;
	self->pending = (mb_range){ 0, 0 };
	return true;
}

uintptr_t mb_threads_futex_wait(mb_threads *t, mb_context *c, uintptr_t addr, uint32_t compare) {
	uint32_t cur=*(uint32_t*)addr; TDBG("futex_wait tid=%u addr=%lx cur=%u cmp=%u\n",t->active_tid,(unsigned long)addr,cur,compare);
	if (cur != compare) return serr(EAGAIN);
	return park_me(t, c, sok(0), addr);
}

mb_sword mb_threads_futex_requeue(mb_threads *t, uintptr_t from, uintptr_t to, uint32_t wake, uint32_t requeue) {
	long count = 0;
	while (wake > 0 || requeue > 0) {
		uint32_t tid; bool more;
		if (unpark_one(t, from, &tid, &more) != 0) break;
		count++;
		if (wake > 0) wake--;
		else { park_other(t, to, tid); requeue--; }
		if (!more) break;
	}
	return count;
}
mb_sword mb_threads_futex_wake(mb_threads *t, uintptr_t addr, uint32_t count) {
	TDBG("futex_wake tid=%u addr=%lx count=%u\n",t->active_tid,(unsigned long)addr,count);
	return mb_threads_futex_requeue(t, addr, 0, count, 0);
}

uintptr_t mb_threads_futex_lock_pi(mb_threads *t, mb_context *c, uintptr_t addr) {
	uint32_t *atom = (uint32_t *)addr;
	if (*atom == 0) { *atom = t->active_tid; return sok(0); }
	*atom |= FUTEX_WAITERS;
	return park_me(t, c, sok(0), addr);
}
uintptr_t mb_threads_futex_unlock_pi(mb_threads *t, mb_context *c, uintptr_t addr) {
	uint32_t *atom = (uint32_t *)addr;
	uint32_t tid; bool more;
	if (unpark_one(t, addr, &tid, &more) == 0) {
		*atom = more ? (tid | FUTEX_WAITERS) : tid;
		return swap_to(t, c, tid, sok(0));   /* fair handoff */
	}
	*atom = 0;
	return sok(0);
}

uint32_t mb_threads_set_tid_address(mb_threads *t, uintptr_t addr) {
	gthread *g = find_thread(t, t->active_tid);
	g->tid_address = addr;
	return g->tid;
}
uint32_t mb_threads_get_tid(mb_threads *t) { return t->active_tid; }
uintptr_t mb_threads_yield(mb_threads *t, mb_context *c) { return swap_to_next(t, c, sok(0)); }

/* ---- savestate (self-consistent; encoding is implementation-defined per SPEC) ---- */
static int wr(mb_write_cb w, uintptr_t ud, const void *d, size_t n) { return w(ud, d, n) < 0 ? -1 : 0; }
static int rd(mb_read_cb r, uintptr_t ud, void *d, size_t n) { uint8_t *p = d; while (n) { intptr_t g = r(ud, p, n); if (g <= 0) return -1; p += g; n -= (size_t)g; } return 0; }

int mb_threads_save(mb_threads *t, mb_context *c, mb_write_cb w, uintptr_t ud) {
	if (t->active_tid != 1) { fprintf(stderr, "miniBox: thread hijack on save\n"); return -1; }
	gthread *main = find_thread(t, 1);
	main->thread_area = c->thread_area; main->rsp = c->guest_rsp;
	if (wr(w, ud, "GuestThreadSet", 14)) return -1;
	if (wr(w, ud, &t->next_tid, 4) || wr(w, ud, &t->active_tid, 4)) return -1;
	uint32_t nt = (uint32_t)t->nthreads;
	if (wr(w, ud, &nt, 4)) return -1;
	for (size_t i = 0; i < t->nthreads; i++) if (wr(w, ud, &t->threads[i], sizeof(gthread))) return -1;
	uint32_t nf = (uint32_t)t->nfut;
	if (wr(w, ud, &nf, 4)) return -1;
	for (size_t i = 0; i < t->nfut; i++) {
		if (wr(w, ud, &t->futicies[i].addr, sizeof(uintptr_t))) return -1;
		uint32_t qn = (uint32_t)t->futicies[i].n;
		if (wr(w, ud, &qn, 4)) return -1;
		if (qn && wr(w, ud, t->futicies[i].tids, qn * sizeof(uint32_t))) return -1;
	}
	if (wr(w, ud, "GuestThreadSet", 14)) return -1;
	return 0;
}

int mb_threads_load(mb_threads *t, mb_context *c, mb_read_cb r, uintptr_t ud) {
	if (t->active_tid != 1) { fprintf(stderr, "miniBox: thread hijack on load\n"); return -1; }
	char magic[14];
	if (rd(r, ud, magic, 14) || memcmp(magic, "GuestThreadSet", 14) != 0) return -1;
	if (rd(r, ud, &t->next_tid, 4) || rd(r, ud, &t->active_tid, 4)) return -1;
	uint32_t nt;
	if (rd(r, ud, &nt, 4)) return -1;
	t->nthreads = 0;
	for (uint32_t i = 0; i < nt; i++) { gthread g; if (rd(r, ud, &g, sizeof(gthread))) return -1; insert_thread(t, g); }
	for (size_t i = 0; i < t->nfut; i++) free(t->futicies[i].tids);
	t->nfut = 0;
	uint32_t nf;
	if (rd(r, ud, &nf, 4)) return -1;
	for (uint32_t i = 0; i < nf; i++) {
		uintptr_t addr; uint32_t qn;
		if (rd(r, ud, &addr, sizeof(uintptr_t)) || rd(r, ud, &qn, 4)) return -1;
		futex_queue *q = get_or_make_queue(t, addr);
		for (uint32_t j = 0; j < qn; j++) { uint32_t tid; if (rd(r, ud, &tid, 4)) return -1; queue_push(q, tid); }
	}
	if (rd(r, ud, magic, 14) || memcmp(magic, "GuestThreadSet", 14) != 0) return -1;
	gthread *main = find_thread(t, 1);
	c->thread_area = main->thread_area; c->guest_rsp = main->rsp;
	return 0;
}
