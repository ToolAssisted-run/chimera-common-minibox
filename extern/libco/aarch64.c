/*
  libco.aarch64: amd64.c for an aarch64 machine, the same cothreads and the
  same allocation, with the switch written for aarch64.
  libco.amd64 (2016-09-14) author: byuu
  license: public domain
*/

#include "libco.h"

#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <emulibc.h>

// allocations are 16k larger than asked for, which is all used as guard space
#define GUARD_SIZE 0x4000

typedef struct {
	// used by coswap.s, has to be at the beginning of the struct
	struct {
		uint64_t sp;
		uint64_t fp; // x29: as rbp on amd64, the compiler will not take it as a clobber
		uint64_t pc;
		uint64_t lr; // x30 on arrival: crash() for a new cothread, which returns through it
	} jmp_buf;
	// points to the lowest address in the stack
	// NB: because of guard space, this is not valid stack
	void* stack;
	// length of the stack that we allocated in bytes
	uint64_t stack_size;
} cothread_impl;

// the cothread that represents the real host thread we started from
static cothread_impl co_host_buffer;
// what cothread are we in right now
static cothread_impl* co_active_handle;

static void free_thread(cothread_impl* co)
{
	if (munmap(co->stack, co->stack_size) != 0)
		abort();
	free(co);
}

static cothread_impl* alloc_thread(uint64_t size)
{
	cothread_impl* co = calloc(1, sizeof(*co));
	if (!co)
		return NULL;

	// align up to 4k
	size = (size + 4095) & ~4095ul;
	size += GUARD_SIZE;

	co->stack = mmap(NULL, size,
		PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	
	if (co->stack == (void*)(-1))
	{
		free(co);
		return NULL;
	}

	if (mprotect(co->stack, GUARD_SIZE, PROT_NONE) != 0)
	{
		free_thread(co);
		return NULL;
	}

	co->stack_size = size;
	return co;
}

static void crash(void)
{
	__asm__("udf #0xf4"); // called only if cothread_t entrypoint returns
}

ECL_EXPORT void co_clean(void)
{
	memset(&co_host_buffer, 0, sizeof(co_host_buffer));
}

cothread_t co_active(void)
{
	if (!co_active_handle)
		co_active_handle = &co_host_buffer;
	return co_active_handle;
}

cothread_t co_create(unsigned int sz, void (*entrypoint)(void))
{
	cothread_impl* co;
	if (!co_active_handle)
		co_active_handle = &co_host_buffer;

	if ((co = alloc_thread(sz)))
	{
		uint64_t p = (uint64_t)((char*)co->stack + co->stack_size); // top of stack, 16-aligned
		co->jmp_buf.sp = p; // stack pointer
		co->jmp_buf.pc = (uint64_t)entrypoint; // start of function
		co->jmp_buf.lr = (uint64_t)crash; // crash if entrypoint returns
	}

	return co;
}

void co_delete(cothread_t handle)
{
	free_thread(handle);
}

void co_switch(cothread_t handle)
{
	cothread_impl* co = handle;
	cothread_impl* co_previous_handle = co_active_handle;
	co_active_handle = co;

	register uint64_t _x0 __asm__("x0") = (uint64_t)co_previous_handle;
	register uint64_t _x1 __asm__("x1") = (uint64_t)co_active_handle;

	// save sp, fp and where to come back; load the other's and go. Everything
	// else is clobbered, as amd64.c clobbers it: the compiler saves what it
	// needs around the switch. lr is stored as 0 for a cothread that is coming
	// back here (it clobbers x30 anyway) and is crash() for a new one.
	__asm__ __volatile__(
		"mov x2, sp\n"
		"str x2, [x0, #0]\n"
		"str x29, [x0, #8]\n"
		"adr x2, 1f\n"
		"str x2, [x0, #16]\n"
		"str xzr, [x0, #24]\n"
		"ldr x2, [x1, #0]\n"
		"mov sp, x2\n"
		"ldr x29, [x1, #8]\n"
		"ldr x30, [x1, #24]\n"
		"ldr x2, [x1, #16]\n"
		"br x2\n"
		"1:\n"
		: "+r"(_x0), "+r"(_x1)
		:
		: "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x30",
			"v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
			"memory", "cc"
	);
}

cothread_t co_derive(void* memory, unsigned sz, void (*entrypoint)(void))
{
	return NULL;
}

int co_serializable(void)
{
	return 0;
}
