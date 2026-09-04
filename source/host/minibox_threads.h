/* Guest green-thread set (threading.c). Cooperative, single running thread. */
#ifndef MINIBOX_THREADS_H
#define MINIBOX_THREADS_H
#include "minibox_internal.h"

typedef struct mb_threads mb_threads;

mb_threads *mb_threads_new(void);
void        mb_threads_free(mb_threads *t);

/* NR_WBX_CLONE(thread_area, child_rsp, child_rip, child_tid, parent_tid) */
mb_sword      mb_threads_spawn(mb_threads *t, mb_block *b, uintptr_t thread_area,
                           uintptr_t guest_rsp, uintptr_t guest_rip, uintptr_t child_tid, uint32_t *parent_tid);
uintptr_t mb_threads_exit(mb_threads *t, mb_context *c);
uintptr_t mb_threads_yield(mb_threads *t, mb_context *c);
uint32_t  mb_threads_set_tid_address(mb_threads *t, uintptr_t addr);
uint32_t  mb_threads_get_tid(mb_threads *t);

bool          mb_threads_hold_stack_unmap(mb_threads *t, mb_range r);
bool          mb_threads_take_held_unmap(mb_threads *t, mb_range *out);
uintptr_t mb_threads_futex_wait(mb_threads *t, mb_context *c, uintptr_t addr, uint32_t compare);
mb_sword      mb_threads_futex_wake(mb_threads *t, uintptr_t addr, uint32_t count);
mb_sword      mb_threads_futex_requeue(mb_threads *t, uintptr_t from, uintptr_t to, uint32_t wake, uint32_t requeue);
uintptr_t mb_threads_futex_lock_pi(mb_threads *t, mb_context *c, uintptr_t addr);
uintptr_t mb_threads_futex_unlock_pi(mb_threads *t, mb_context *c, uintptr_t addr);

int mb_threads_save(mb_threads *t, mb_context *c, mb_write_cb w, uintptr_t ud);
int mb_threads_load(mb_threads *t, mb_context *c, mb_read_cb r, uintptr_t ud);

#endif
