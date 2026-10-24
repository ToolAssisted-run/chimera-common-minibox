/* Guest green-thread set (threading.c). Cooperative, single running thread. */
#ifndef MINIBOX_THREADS_H
#define MINIBOX_THREADS_H
#include "minibox_internal.h"

typedef struct mb_threads mb_threads;

mb_threads *mb_threads_new(void);
void        mb_threads_free(mb_threads *t);

/* machine-spec version the guest declared (2 when it says nothing); the host
 * sets it at load from __wbx_machine_spec */
void mb_threads_set_spec(mb_threads *t, int spec);
int  mb_threads_spec(const mb_threads *t);
/* the guest kit's revision (MACHINE-SPEC, "Guest kit revisions"): from 2 the
 * v3 clock saturates instead of wrapping, and a lone yield or an expired wait
 * lets time move */
void     mb_threads_set_kit_revision(mb_threads *t, uint32_t revision);
uint32_t mb_threads_kit_revision(const mb_threads *t);
/* v3, revision 2: a timespec as nanoseconds, the largest there is when it
 * would not fit; a sum of two of them the same way */
uint64_t mb_threads_ns_of(const mb_threads *t, int64_t sec, int64_t nsec);
uint64_t mb_threads_ns_add(const mb_threads *t, uint64_t a, uint64_t b);
/* sched_yield: v3 and revision 2, the only runnable thread costs a tick */
uintptr_t mb_threads_sched_yield(mb_threads *t, mb_context *c);

/* NR_WBX_CLONE(thread_area, child_rsp, child_rip, child_tid, parent_tid) */
mb_sword      mb_threads_spawn(mb_threads *t, mb_block *b, uintptr_t thread_area,
                           uintptr_t guest_rsp, uintptr_t guest_rip, uintptr_t child_tid, uint32_t *parent_tid);
uintptr_t mb_threads_exit(mb_threads *t, mb_context *c);
uintptr_t mb_threads_yield(mb_threads *t, mb_context *c);
uint32_t  mb_threads_set_tid_address(mb_threads *t, uintptr_t addr);
uint32_t  mb_threads_get_tid(mb_threads *t);
uint32_t  mb_threads_active_tid(mb_threads *t);

bool          mb_threads_hold_stack_unmap(mb_threads *t, mb_range r);
bool          mb_threads_take_held_unmap(mb_threads *t, mb_range *out);
/* v3 virtual time: the clock tick (constant, written in the spec), and the
 * second the clock starts at (the v2 constant; absolute v3 times live on the
 * clock's own scale, so the host converts them by this) */
#define MB_V3_TICK_NS 1000ull
#define MB_V3_BASE_SEC 1495889068ull
#define MB_V3_BASE_NS (MB_V3_BASE_SEC * 1000000000ull)
/* The latest second a machine may be told to start at (wbx_set_clock_start):
 * 2200-01-01, so that the start plus the longest clock fits in 64 bits of
 * nanoseconds whatever start was chosen. */
#define MB_CLOCK_START_MAX_SEC 7258118400ull

uintptr_t mb_threads_futex_wait(mb_threads *t, mb_context *c, uintptr_t addr, uint32_t compare);
mb_sword      mb_threads_futex_wake(mb_threads *t, uintptr_t addr, uint32_t count);
mb_sword      mb_threads_futex_requeue(mb_threads *t, uintptr_t from, uintptr_t to, uint32_t wake, uint32_t requeue);
uintptr_t mb_threads_futex_lock_pi(mb_threads *t, mb_context *c, uintptr_t addr);
uintptr_t mb_threads_futex_unlock_pi(mb_threads *t, mb_context *c, uintptr_t addr);

/* v3 virtual time */
uint64_t  mb_threads_clock_ns(mb_threads *t);
void      mb_threads_advance(mb_threads *t, uint64_t ns);
uintptr_t mb_threads_futex_wait_timeout(mb_threads *t, mb_context *c, uintptr_t addr, uint32_t compare, bool has_deadline, uint64_t deadline);
uintptr_t mb_threads_yield_value(mb_threads *t, mb_context *c, uintptr_t ret);

int mb_threads_save(mb_threads *t, mb_context *c, mb_write_cb w, uintptr_t ud);
int mb_threads_load(mb_threads *t, mb_context *c, mb_read_cb r, uintptr_t ud);

/* whether a thread of that id exists (tkill with signal 0 asks) */
bool mb_threads_has_thread(mb_threads *t, uint32_t tid);
/* before loading a state onto a machine that died on another thread than its
 * first: a thread set only loads onto the first, and the load replaces them all */
void mb_threads_reset_active(mb_threads *t);

#endif
