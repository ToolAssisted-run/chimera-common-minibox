#define _GNU_SOURCE   /* pthread_kill, SA_SIGINFO under -std=c11 */
/* A signal the host's runtime sends itself, landing while guest code runs.
 *
 * Mono stops every thread for its collector with a signal, and its handler is
 * host code that reads its thread locals. The handler here was installed
 * before miniBox, as a runtime's is, and does the same: it checks a thread
 * local of its own and that pthread_self() is the thread it was sent to. The
 * guest runs with its own thread pointer in, so unless miniBox puts the host's
 * back for the handler, both are read through the guest's.
 *
 * The handler must not run on the guest's STACK either, which is where the
 * kernel puts its frame for a handler without SA_ONSTACK: that writes host
 * data into guest memory, and a frame that reaches a clean (write-protected)
 * tracked page cannot be delivered at all - Mono's suspend handler waits in
 * sigsuspend for the restart signal, whose frame went one page further down
 * and killed Chimera with a kernel SIGSEGV. */
#include "minibox.h"
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { FILE *f; } fr_t;
static intptr_t file_read(uintptr_t ud, uint8_t *d, uintptr_t s){return (intptr_t)fread(d,1,s,((fr_t*)ud)->f);}

static int fails = 0;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "  FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

#define CANARY 0x5eed5eed5eed5eedull
static __thread volatile uint64_t t_canary = CANARY;
static pthread_t g_main;
static atomic_int g_seen, g_wrong, g_on_guest_stack, g_done;
/* an address on the guest's stack; the handler's frame must be nowhere near */
static uintptr_t g_guest_stack;
#define NEAR (64u << 20)

static void runtime_handler(int sig, siginfo_t *info, void *uc) {
	(void)sig; (void)info; (void)uc;
	volatile uint8_t here = 0;
	const uintptr_t sp = (uintptr_t)&here;
	if (sp > g_guest_stack - NEAR && sp < g_guest_stack + NEAR) atomic_fetch_add(&g_on_guest_stack, 1);
	if (t_canary != CANARY || !pthread_equal(pthread_self(), g_main)) atomic_fetch_add(&g_wrong, 1);
	atomic_fetch_add(&g_seen, 1);
}

static void *sender(void *arg) {
	(void)arg;
	const struct timespec gap = { 0, 200000 };   /* 0.2 ms */
	while (!atomic_load(&g_done)) {
		pthread_kill(g_main, SIGUSR1);
		nanosleep(&gap, NULL);
	}
	return NULL;
}

typedef int (*init_fn)(void);
typedef uint64_t (*spin_fn)(uint64_t);
static uintptr_t proc(mb_host *h, const char *n){mb_return r;wbx_get_proc_addr(h,n,&r);if(r.error_message[0]){fprintf(stderr,"proc %s:%s\n",n,r.error_message);exit(2);}return r.data;}

int main(int argc, char **argv) {
	g_main = pthread_self();
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = runtime_handler;
	sa.sa_flags = SA_SIGINFO | SA_RESTART;
	sigemptyset(&sa.sa_mask);
	CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);

	const char *path = argc > 1 ? argv[1] : "guest_spin.wbx";
	FILE *f = fopen(path, "rb");
	if (!f) { fprintf(stderr, "cannot open %s\n", path); return 1; }
	mb_memory_layout_template layout = { 16u<<20, 4u<<20, 4u<<20, 4u<<20, 16u<<20 };
	fr_t fr = { f };
	mb_return r;
	wbx_create_host(&layout, "guest_spin.wbx", file_read, (uintptr_t)&fr, &r);
	fclose(f);
	if (r.error_message[0]) { fprintf(stderr, "create: %s\n", r.error_message); return 1; }
	mb_host *h = (mb_host *)r.data;
	wbx_activate_host(h, &r);
	CHECK(((init_fn)proc(h, "Init"))() == 1);
	spin_fn Spin = (spin_fn)proc(h, "Spin");
	g_guest_stack = (uintptr_t)((spin_fn)proc(h, "StackHere"))(0);

	pthread_t s;
	CHECK(pthread_create(&s, NULL, sender, NULL) == 0);
	/* guest code for most of a second, under a signal every 0.2 ms */
	const uint64_t n = 200000000;
	uint64_t spun = 0;
	for (int i = 0; i < 4 && fails == 0; i++) spun = Spin(n);
	atomic_store(&g_done, 1);
	pthread_join(s, NULL);
	wbx_deactivate_host(h, &r);
	wbx_destroy_host(h, &r);

	printf("Spin -> %llu; %d signals handled, %d under the wrong thread pointer, %d on the guest's stack (near %#lx)\n",
	       (unsigned long long)spun, atomic_load(&g_seen), atomic_load(&g_wrong),
	       atomic_load(&g_on_guest_stack), (unsigned long)g_guest_stack);
	CHECK(spun == n);
	CHECK(atomic_load(&g_seen) > 100);
	CHECK(atomic_load(&g_wrong) == 0);
	CHECK(atomic_load(&g_on_guest_stack) == 0);
	if (fails == 0) printf("run_foreign_signal: all checks passed\n");
	return fails ? 1 : 0;
}
