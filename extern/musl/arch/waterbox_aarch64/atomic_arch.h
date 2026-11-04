#include "syscall.h"

/* arch/waterbox's atomics, for an aarch64 guest: one guest thread runs at a
 * time and every switch between them is a syscall, so musl's own atomics are
 * plain memory operations here exactly as they are on x86-64. The CPU-specific
 * ones (crash, bit scans) are aarch64's. */

#define a_cas a_cas
static inline int a_cas(volatile int *p, int t, int s)
{
	int old = *p;
	if (old == t) *p = s;
	return old;
}

#define a_cas_p a_cas_p
static inline void *a_cas_p(volatile void *p, void *t, void *s)
{
	void *old = *(void *volatile *)p;
	if (old == t) *(void *volatile *)p = s;
	return old;
}

#define a_swap a_swap
static inline int a_swap(volatile int *p, int v)
{
	int ret = *p;
	*p = v;
	return ret;
}

#define a_fetch_add a_fetch_add
static inline int a_fetch_add(volatile int *p, int v)
{
	int ret = *p;
	*p += v;
	return ret;
}

#define a_and a_and
static inline void a_and(volatile int *p, int v)
{
	*p &= v;
}

#define a_or a_or
static inline void a_or(volatile int *p, int v)
{
	*p |= v;
}

#define a_and_64 a_and_64
static inline void a_and_64(volatile uint64_t *p, uint64_t v)
{
	*p &= v;
}

#define a_or_64 a_or_64
static inline void a_or_64(volatile uint64_t *p, uint64_t v)
{
	*p |= v;
}

#define a_inc a_inc
static inline void a_inc(volatile int *p)
{
	(*p)++;
}

#define a_dec a_dec
static inline void a_dec(volatile int *p)
{
	(*p)--;
}

#define a_store a_store
static inline void a_store(volatile int *p, int x)
{
	*p = x;
}

#define a_barrier a_barrier
static inline void a_barrier()
{
	__asm__ __volatile__( "" : : : "memory" );
}

#define a_spin a_spin
static inline void a_spin()
{
	syscall(SYS_sched_yield);
}

/* udf #0xf4: the host's fault handler names it as the guest stopping itself
 * (tripguard.c), as it does x86-64's hlt */
#define a_crash a_crash
static inline void a_crash()
{
	__asm__ __volatile__( "udf #0xf4" : : : "memory" );
}

#define a_ctz_64 a_ctz_64
static inline int a_ctz_64(uint64_t x)
{
	__asm__( "rbit %0, %1 ; clz %0, %0" : "=r"(x) : "r"(x) );
	return x;
}

#define a_clz_64 a_clz_64
static inline int a_clz_64(uint64_t x)
{
	__asm__( "clz %0, %1" : "=r"(x) : "r"(x) );
	return x;
}
