/* A guest that only spins, and has thread locals - so it runs with its own
 * thread pointer installed (fs_swap), which is the window a host signal can
 * land in. */
#include <emulibc.h>
#include <stdint.h>

static _Thread_local volatile uint64_t t_spun;

ECL_EXPORT int Init(void) { return 1; }

/* an address on the guest's stack */
ECL_EXPORT uint64_t StackHere(void) {
	volatile uint8_t here = 0;
	return (uint64_t)(uintptr_t)&here;
}

/* spins n times; returns n, counted in a thread local */
ECL_EXPORT uint64_t Spin(uint64_t n) {
	t_spun = 0;
	for (uint64_t i = 0; i < n; i++) t_spun++;
	return t_spun;
}
