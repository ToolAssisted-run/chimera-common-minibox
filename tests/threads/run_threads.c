#define _GNU_SOURCE   /* sigset_t and pthread_sigmask under -std=c11 */
/* Drives the pthreaded guest through the host: proves green threads, futex-
 * backed mutexes/condvars, join, and a savestate taken with threads present. */
#include "minibox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <pthread.h>
#include <time.h>
#endif

typedef struct { FILE *f; } fr_t;
static intptr_t file_read(uintptr_t ud, uint8_t *d, uintptr_t s){return (intptr_t)fread(d,1,s,((fr_t*)ud)->f);}
typedef struct { uint8_t *b; size_t len, cap, pos; } mb_t;
static int32_t mem_write(uintptr_t ud,const uint8_t*d,uintptr_t n){mb_t*m=(mb_t*)ud;if(m->len+n>m->cap){m->cap=(m->len+n)*2+64;m->b=realloc(m->b,m->cap);}memcpy(m->b+m->len,d,n);m->len+=n;return 0;}
static intptr_t mem_read(uintptr_t ud,uint8_t*d,uintptr_t n){mb_t*m=(mb_t*)ud;uintptr_t a=m->len-m->pos;if(n>a)n=a;memcpy(d,m->b+m->pos,n);m->pos+=n;return (intptr_t)n;}

static int fails = 0;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "  FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

typedef int (MB_GUEST_ABI *init_fn)(void);
typedef uint64_t (MB_GUEST_ABI *run_fn)(void);
typedef uint64_t (MB_GUEST_ABI *run1_fn)(uint64_t);
static uintptr_t proc(mb_host *h, const char *n){mb_return r;wbx_get_proc_addr(h,n,&r);if(r.error_message[0]){fprintf(stderr,"proc %s:%s\n",n,r.error_message);exit(2);}return r.data;}

/* Asks for a stop from another thread, as a frontend's watchdog does: after
 * 200 ms, and again every 50 ms until the call comes back. A stop that never
 * lands would hang the test, so after 10 seconds of asking it fails it. */
struct stopper { mb_host *h; volatile int done; int asked; };
static void sleep_ms(int ms) {
#ifdef _WIN32
	Sleep((DWORD)ms);
#else
	struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
	nanosleep(&ts, NULL);
#endif
}
#ifdef _WIN32
static DWORD WINAPI stopper_fn(LPVOID arg)
#else
static void *stopper_fn(void *arg)
#endif
{
	struct stopper *s = (struct stopper *)arg;
	sleep_ms(200);
	while (!s->done) {
		mb_return r;
		wbx_stop_guest(s->h, "stopped by the test after 200 ms", &r);
		if (++s->asked == 200) {
			fprintf(stderr, "  FAIL: a guest looping in its own fault handler was not stopped after %d asks\n", s->asked);
			fflush(stdout);
			fflush(stderr);
			_Exit(1);
		}
		sleep_ms(50);
	}
	return 0;
}

int main(int argc, char **argv) {
	const char *path = argc > 1 ? argv[1] : "guest_threads.wbx";
	FILE *f = fopen(path, "rb");
	if (!f) { fprintf(stderr, "cannot open %s\n", path); return 1; }
	mb_memory_layout_template layout = { 64u<<20, 16u<<20, 16u<<20, 16u<<20, 64u<<20 };
	fr_t fr = { f };
	mb_return r;
	wbx_create_host(&layout, "guest_threads.wbx", file_read, (uintptr_t)&fr, &r);
	fclose(f);
	if (r.error_message[0]) { fprintf(stderr, "create: %s\n", r.error_message); return 1; }
	mb_host *h = (mb_host *)r.data;

	wbx_activate_host(h, &r);
	CHECK(((init_fn)proc(h, "Init"))() == 1);
	run_fn RunThreads = (run_fn)proc(h, "RunThreads");
	run1_fn RunCondvar = (run1_fn)proc(h, "RunCondvar");
	run_fn RunTls = (run_fn)proc(h, "RunTls");
	run_fn RunGuestFault = (run_fn)proc(h, "RunGuestFault");
	run_fn RunGuestFaultDeath = (run_fn)proc(h, "RunGuestFaultDeath");
	run_fn RunHostWriteFault = (run_fn)proc(h, "RunHostWriteFault");
	run_fn RunFaultYield = (run_fn)proc(h, "RunFaultYield");
	run_fn RunFaultRegisters = (run_fn)proc(h, "RunFaultRegisters");
	run_fn RunGuestFaultDeclined = (run_fn)proc(h, "RunGuestFaultDeclined");
	run_fn CallNullWithOwnFs = (run_fn)proc(h, "CallNullWithOwnFs");
	run_fn SpinInFaultHandler = (run_fn)proc(h, "SpinInFaultHandler");
	wbx_deactivate_host(h, &r); wbx_seal(h, &r);
	if (r.error_message[0]) { fprintf(stderr, "seal: %s\n", r.error_message); return 1; }
	wbx_activate_host(h, &r);

	/* 4 threads x 1000 increments under a futex mutex -> exactly 4000 */
	uint64_t total = RunThreads();
	printf("RunThreads -> %llu (expect 4000)\n", (unsigned long long)total);
	CHECK(total == 4000);

	/* condvar producer/consumer -> value*2+1 */
	uint64_t cv = RunCondvar(21);
	printf("RunCondvar(21) -> %llu (expect 43)\n", (unsigned long long)cv);
	CHECK(cv == 43);
	{
		const uint64_t tls = RunTls();
		printf("RunTls -> %#llx (expect 0: thread locals zeroed, initialised, apart from the stack)\n", (unsigned long long)tls);
		CHECK(tls == 0);
		const uint64_t gf = RunGuestFault();
		printf("RunGuestFault -> %#llx (expect 0: the guest's fault handler runs as guest code, and may fault)\n", (unsigned long long)gf);
		CHECK(gf == 0);
		const uint64_t hf = RunHostWriteFault();
		printf("RunHostWriteFault -> %#llx (expect 0: a fault taken in host code reaches the guest's handler, whose system call works)\n", (unsigned long long)hf);
		CHECK(hf == 0);
		const uint64_t fy = RunFaultYield();
		printf("RunFaultYield -> %#llx (expect 0: a handler that gives way to a thread that faults too; each runs on its own stack)\n", (unsigned long long)fy);
		CHECK(fy == 0);
		const uint64_t fr = RunFaultRegisters();
		printf("RunFaultRegisters -> %#llx (expect 0: the faulting code's registers and flags are back after the handler)\n", (unsigned long long)fr);
		CHECK(fr == 0);
		/* A frontend's tool reads a page the guest made no-access, from a
		 * thread outside the guest. Through the read view the bytes are there
		 * and the guest's handler does not run: before it, such a read ran
		 * the handler and could change the machine (engine analysis,
		 * 2026-10-18). Through the guest's own view it runs - the control. */
		{
			run_fn WatchForHostRead = (run_fn)proc(h, "WatchForHostRead");
			run_fn HandlerRuns = (run_fn)proc(h, "HandlerRuns");
			run_fn EndHostRead = (run_fn)proc(h, "EndHostRead");
			const uint64_t page = WatchForHostRead();
			CHECK(page != 0);
			const uint64_t before = HandlerRuns();
			wbx_guest_read_view(h, (uintptr_t)page, 4096, &r);
			CHECK(!r.error_message[0] && r.data != 0);
			int same = r.data != 0;
			for (int i = 0; same && i < 4096; i++)
				if (((const uint8_t *)r.data)[i] != (uint8_t)(i * 7 + 3)) same = 0;
			CHECK(same);
			const uint64_t afterView = HandlerRuns();
			printf("read view -> the bytes %s, the guest's handler ran %llu times (expect 0)\n",
				same ? "are there" : "DIFFER", (unsigned long long)(afterView - before));
			CHECK(afterView == before);
			const uint8_t direct = *(volatile const uint8_t *)(uintptr_t)(page + 1);
			const uint64_t afterDirect = HandlerRuns();
			printf("direct read -> %u, the guest's handler ran %llu times (expect 1: the control)\n",
				direct, (unsigned long long)(afterDirect - afterView));
			CHECK(direct == 10);
			CHECK(afterDirect == afterView + 1);
			CHECK(EndHostRead() == 1);
			/* outside the guest's memory, and empty: refused */
			wbx_guest_read_view(h, (uintptr_t)&fails, sizeof fails, &r);
			CHECK(r.error_message[0] != 0);
			wbx_guest_read_view(h, (uintptr_t)page, 0, &r);
			CHECK(r.error_message[0] != 0);
		}
		/* a machine that died in one of these answered 0 as well */
		char why[512];
		wbx_get_death(h, why, sizeof why, &r);
		CHECK(r.data == 0);
	}

	/* determinism: identical results on repeat */
	CHECK(RunThreads() == 4000);
	CHECK(RunCondvar(100) == 201);

	/* savestate round-trip between thread runs (threads quiescent at tid 1) */
	mb_t st = {0};
	wbx_deactivate_host(h, &r); wbx_save_state(h, mem_write, (uintptr_t)&st, &r); wbx_activate_host(h, &r);
	CHECK(!r.error_message[0]);
	uint64_t after_save = RunThreads();
	st.pos = 0;
	wbx_deactivate_host(h, &r); wbx_load_state(h, mem_read, (uintptr_t)&st, &r); wbx_activate_host(h, &r);
	CHECK(!r.error_message[0]);
	CHECK(RunThreads() == after_save);

	/* A guest that dies inside its own fault handler: the machine dies and the
	 * host lives on, with this thread out of every handler frame - its signal
	 * mask what it was, and the next fault on it not taken for one nested in a
	 * handler that is gone. */
	{
#ifndef _WIN32
		sigset_t mask_before, mask_after;
		pthread_sigmask(SIG_BLOCK, NULL, &mask_before);
#endif
		RunGuestFaultDeath();
		char why[512];
		wbx_get_death(h, why, sizeof why, &r);
		printf("RunGuestFaultDeath -> dead=%llu: %s\n", (unsigned long long)r.data, why);
		CHECK(r.data == 1);
		CHECK(strstr(why, "crashed") != NULL);
#ifndef _WIN32
		pthread_sigmask(SIG_BLOCK, NULL, &mask_after);
		for (int sig = 1; sig < 32; sig++) CHECK(sigismember(&mask_before, sig) == sigismember(&mask_after, sig));
#endif
		st.pos = 0;
		wbx_deactivate_host(h, &r); wbx_load_state(h, mem_read, (uintptr_t)&st, &r); wbx_activate_host(h, &r);
		CHECK(!r.error_message[0]);
		CHECK(RunThreads() == after_save);   /* faults again, outside any handler */
	}
	/* A null call from a guest that owns %fs: its death, and the host's own
	 * thread pointer is back afterwards. */
	{
		CallNullWithOwnFs();
		char why[512];
		wbx_get_death(h, why, sizeof why, &r);
		printf("CallNullWithOwnFs -> dead=%llu: %s\n", (unsigned long long)r.data, why);
		CHECK(r.data == 1);
		CHECK(strstr(why, "crashed") != NULL);
		st.pos = 0;
		wbx_deactivate_host(h, &r); wbx_load_state(h, mem_read, (uintptr_t)&st, &r); wbx_activate_host(h, &r);
		CHECK(!r.error_message[0]);
		CHECK(RunThreads() == after_save);
	}
	/* A protected page the handler does not claim: the machine's death, as
	 * with no handler at all, and the host lives on. */
	{
		RunGuestFaultDeclined();
		char why[512];
		wbx_get_death(h, why, sizeof why, &r);
		printf("RunGuestFaultDeclined -> dead=%llu: %s\n", (unsigned long long)r.data, why);
		CHECK(r.data == 1);
		CHECK(strstr(why, "crashed") != NULL);
		st.pos = 0;
		wbx_deactivate_host(h, &r); wbx_load_state(h, mem_read, (uintptr_t)&st, &r); wbx_activate_host(h, &r);
		CHECK(!r.error_message[0]);
		CHECK(RunThreads() == after_save);
	}

	/* A guest that loops for ever inside its own fault handler is stopped from
	 * another thread - twice, so the first stop is seen to leave nothing
	 * behind that keeps the next one from landing. On Windows, where the
	 * handler runs inside the host's, it was never stopped (chimera#363). */
	for (int k = 0; k < 2; k++) {
		wbx_stop_from_here(h, &r);
		struct stopper s = { h, 0, 0 };
#ifdef _WIN32
		HANDLE t = CreateThread(NULL, 0, stopper_fn, &s, 0, NULL);
#else
		pthread_t t;
		pthread_create(&t, NULL, stopper_fn, &s);
#endif
		const uint64_t got = SpinInFaultHandler();
		s.done = 1;
#ifdef _WIN32
		WaitForSingleObject(t, INFINITE);
		CloseHandle(t);
#else
		pthread_join(t, NULL);
#endif
		char why[512];
		wbx_get_death(h, why, sizeof why, &r);
		printf("SpinInFaultHandler -> %#llx, dead=%llu, after %d asks: %s\n", (unsigned long long)got,
		       (unsigned long long)r.data, s.asked, why);
		CHECK(got == 0 && r.data == 1 && strstr(why, "stopped by the test after 200 ms") != NULL);
		wbx_stop_cancel(h, &r);
		st.pos = 0;
		wbx_deactivate_host(h, &r); wbx_load_state(h, mem_read, (uintptr_t)&st, &r); wbx_activate_host(h, &r);
		CHECK(!r.error_message[0]);
		CHECK(RunThreads() == after_save);
		CHECK(RunGuestFault() == 0);   /* the handler runs again, as at first */
	}

	wbx_deactivate_host(h, &r); wbx_destroy_host(h, &r);
	free(st.b);
	if (fails == 0) printf("run_threads: all checks passed\n");
	else printf("run_threads: %d checks FAILED\n", fails);
	return fails ? 1 : 0;
}
