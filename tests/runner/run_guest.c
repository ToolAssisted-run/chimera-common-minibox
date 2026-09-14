#define _GNU_SOURCE   /* setenv/unsetenv for the abort check; this file is built -std=c11 */
/* End-to-end + corner-case system test: loads guest.wbx through the miniBox C
 * host and exercises the whole phase-1 stack - ELF load, __wbxsysinfo, guest
 * execution via the interop trampolines, guest syscalls (stderr, brk, a mounted
 * file read), sealed/invisible memory, a guest->host callback, savestate
 * round-trip + determinism, and the error/poison paths. */
#include "minibox.h"
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { FILE *f; } freader;
static intptr_t file_read(uintptr_t ud, uint8_t *data, uintptr_t size) {
	return (intptr_t)fread(data, 1, size, ((freader *)ud)->f);
}
typedef struct { const uint8_t *p; size_t n, pos; } memreader;
static intptr_t mem_reader(uintptr_t ud, uint8_t *data, uintptr_t size) {
	memreader *m = (memreader *)ud;
	size_t take = size < (m->n - m->pos) ? size : (m->n - m->pos);
	memcpy(data, m->p + m->pos, take); m->pos += take; return (intptr_t)take;
}
typedef struct { uint8_t *buf; size_t len, cap, pos; } membuf;
static int32_t mem_write(uintptr_t ud, const uint8_t *data, uintptr_t n) {
	membuf *m = (membuf *)ud;
	if (m->len + n > m->cap) { m->cap = (m->len + n) * 2 + 64; m->buf = realloc(m->buf, m->cap); }
	memcpy(m->buf + m->len, data, n); m->len += n; return 0;
}
static intptr_t mem_read(uintptr_t ud, uint8_t *data, uintptr_t n) {
	membuf *m = (membuf *)ud;
	uintptr_t avail = m->len - m->pos; if (n > avail) n = avail;
	memcpy(data, m->buf + m->pos, n); m->pos += n; return (intptr_t)n;
}

static int fails = 0;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "  FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/* guest->host callback (slot 0): record the last logged accumulator value.
 *
 * MB_GUEST_ABI is NOT decoration: the guest calls this through the interop blob,
 * which is sysv64. Compiled win64 on Windows, the callee would spill registers
 * into 32 bytes of shadow space that a sysv64 caller never reserved - straight
 * over the blob's own stack - and the return path would then read a garbage
 * context pointer and fault. Any callback handed to wbx_get_callback_addr needs
 * this. */
static uint64_t g_last_log = 0;
static uintptr_t MB_GUEST_ABI log_cb(uintptr_t v, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t a6) {
	(void)a2;(void)a3;(void)a4;(void)a5;(void)a6; g_last_log = (uint32_t)v; return 0;
}

/* The guest is sysv64 whatever the host is; MB_GUEST_ABI (minibox.h) makes that
 * explicit, which matters on a win64 host and expands to nothing on Linux. */
typedef int      (MB_GUEST_ABI *init_fn)(void);
typedef uint32_t (MB_GUEST_ABI *step_fn)(uint32_t);
typedef uint64_t (MB_GUEST_ABI *getacc_fn)(void);
typedef void     (MB_GUEST_ABI *setcb_fn)(uintptr_t);

static uintptr_t proc(mb_host *h, const char *name) {
	mb_return r; wbx_get_proc_addr(h, name, &r);
	if (r.error_message[0]) { fprintf(stderr, "get_proc_addr(%s): %s\n", name, r.error_message); exit(2); }
	return r.data;
}

/* create a fresh host from the guest path, with the seed file mounted */
static mb_host *make_host(const char *path, uint32_t seed) {
	FILE *f = fopen(path, "rb");
	if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
	mb_memory_layout_template layout = {
		.sbrk_size = 16u<<20, .sealed_size = 16u<<20, .invis_size = 16u<<20,
		.plain_size = 16u<<20, .mmap_size = 32u<<20,
	};
	freader fr = { f };
	mb_return r;
	wbx_create_host(&layout, "guest.wbx", file_read, (uintptr_t)&fr, &r);
	fclose(f);
	if (r.error_message[0]) { fprintf(stderr, "create_host: %s\n", r.error_message); exit(1); }
	mb_host *h = (mb_host *)r.data;
	/* mount the seed as a readonly file BEFORE Init/seal (stable across states) */
	memreader mr = { (const uint8_t *)&seed, sizeof(seed), 0 };
	wbx_mount_file(h, "seed", mem_reader, (uintptr_t)&mr, false, &r);
	CHECK(!r.error_message[0]);
	return h;
}

static void seal_and_activate(mb_host *h) {
	mb_return r;
	fprintf(stderr, "[stage] sealing\n"); fflush(stderr);
	wbx_deactivate_host(h, &r);
	wbx_seal(h, &r);
	if (r.error_message[0]) { fprintf(stderr, "seal: %s\n", r.error_message); exit(1); }
	wbx_activate_host(h, &r);
}

/* Stage markers on stderr, which is unbuffered: when the host aborts or the
 * process dies, buffered stdout is lost, and the last thing seen is whatever the
 * GUEST printed (its writes go through the host's stderr). That reads as "it
 * stopped right after guest init" no matter where it really stopped. */
#define STAGE(...) do { fprintf(stderr, "[stage] " __VA_ARGS__); fputc('\n', stderr); fflush(stderr); } while (0)

/* The child half of the abort check: make a host, let the guest abort. It does
 * not come back - the host's trap takes this process down, which is the point. */
static int abort_child(const char *guest) {
	mb_return r;
	mb_host *h = make_host(guest, 0xABCD);
	wbx_activate_host(h, &r);
	typedef void (MB_GUEST_ABI *abort_fn)(void);
	((abort_fn)proc(h, "Abort"))();
	printf("run_guest --abort-child: the guest's abort() returned\n");
	return 3;
}

/* A guest that aborts must leave its reason in the diagnostic log: the trap's
 * own banner naming the abort, and what the guest last wrote to stderr. Run in a
 * child, since the abort ends the process that runs it. */
static int guest_abort_is_reported(const char *self, const char *guest) {
#ifdef _WIN32
	(void)self; (void)guest;
	printf("run_guest: abort report not checked on Windows (a crashing child raises Windows Error Reporting)\n");
	return 1;
#else
	const char *dir = getenv("TMPDIR");
	if (dir == NULL || dir[0] == '\0') dir = "/tmp";
	char log[512], cmd[2048];
	snprintf(log, sizeof log, "%s/run_guest_abort_%ld.log", dir, (long)time(NULL));
	remove(log);
	setenv("MINIBOX_LOG", log, 1);
	snprintf(cmd, sizeof cmd, "'%s' --abort-child '%s' >/dev/null 2>&1", self, guest);
	int status = system(cmd);
	unsetenv("MINIBOX_LOG");
	static char text[64 * 1024];
	size_t n = 0;
	FILE *f = fopen(log, "rb");
	if (f != NULL) { n = fread(text, 1, sizeof text - 1, f); fclose(f); }
	text[n] = '\0';
	remove(log);
	const bool died = status != 0;
	const bool named = strstr(text, "the guest aborted") != NULL;
	const bool words = strstr(text, "conformance guest: these are my last words") != NULL;
	printf("run_guest: abort child died=%d, log names the abort=%d, log has the guest's words=%d\n", died, named, words);
	return died && named && words;
#endif
}

int main(int argc, char **argv) {
	if (argc > 2 && strcmp(argv[1], "--abort-child") == 0) return abort_child(argv[2]);
	const char *path = argc > 1 ? argv[1] : "guest.wbx";
	mb_return r;

	setvbuf(stdout, NULL, _IONBF, 0);
	STAGE("start, guest=%s", path);

	/* ---- main run: init, callback, seal, steps, savestate round-trip ---- */
	mb_host *h = make_host(path, 0xABCD);
	STAGE("host created + guest mounted");
	wbx_activate_host(h, &r);
	STAGE("activated");

	STAGE("resolving guest exports");
	init_fn Init = (init_fn)proc(h, "Init");
	step_fn Step = (step_fn)proc(h, "Step");
	getacc_fn GetAcc = (getacc_fn)proc(h, "GetAcc");
	setcb_fn SetLogCallback = (setcb_fn)proc(h, "SetLogCallback");

	/* register a host callback in slot 0 and hand its guest-visible thunk over */
	wbx_get_callback_addr(h, log_cb, 0, &r);
	CHECK(!r.error_message[0]);
	SetLogCallback(r.data);

	STAGE("calling guest Init");
	CHECK(Init() == 1);
	STAGE("Init returned");
	seal_and_activate(h);

	STAGE("stepping the guest");
	uint32_t s1 = Step(0x11111111);
	uint32_t s2 = Step(0x22222222);
	STAGE("steps done");
	uint64_t acc_at_save = GetAcc();
	CHECK(g_last_log == (uint32_t)acc_at_save);   /* the guest->host callback fired */

	membuf state = {0};
	wbx_deactivate_host(h, &r);
	wbx_save_state(h, mem_write, (uintptr_t)&state, &r);
	CHECK(!r.error_message[0]);
	wbx_activate_host(h, &r);

	uint32_t s3 = Step(0x33333333);
	CHECK(GetAcc() != acc_at_save);

	state.pos = 0;
	wbx_deactivate_host(h, &r);
	wbx_load_state(h, mem_read, (uintptr_t)&state, &r);
	CHECK(!r.error_message[0]);
	wbx_activate_host(h, &r);
	CHECK(GetAcc() == acc_at_save);
	CHECK(Step(0x33333333) == s3);   /* deterministic replay from the restored point */

	wbx_deactivate_host(h, &r);
	wbx_destroy_host(h, &r);

	/* ---- determinism across two independent hosts, same seed ---- */
	mb_host *h2 = make_host(path, 0xABCD);
	wbx_activate_host(h2, &r);
	((setcb_fn)proc(h2, "SetLogCallback"))(0);   /* no callback this time */
	CHECK(((init_fn)proc(h2, "Init"))() == 1);
	wbx_deactivate_host(h2, &r); wbx_seal(h2, &r); wbx_activate_host(h2, &r);
	uint32_t a = ((step_fn)proc(h2, "Step"))(0x11111111);
	uint32_t bb = ((step_fn)proc(h2, "Step"))(0x22222222);
	CHECK(a == s1 && bb == s2);   /* same seed + inputs -> identical results */
	wbx_deactivate_host(h2, &r); wbx_destroy_host(h2, &r);

	/* ---- different seed -> different result ---- */
	mb_host *h3 = make_host(path, 0x9999);
	wbx_activate_host(h3, &r);
	((setcb_fn)proc(h3, "SetLogCallback"))(0);
	((init_fn)proc(h3, "Init"))();
	wbx_deactivate_host(h3, &r); wbx_seal(h3, &r); wbx_activate_host(h3, &r);
	CHECK(((step_fn)proc(h3, "Step"))(0x11111111) != s1);
	wbx_deactivate_host(h3, &r); wbx_destroy_host(h3, &r);

	/* ---- error paths ---- */
	/* save before seal -> error */
	mb_host *he = make_host(path, 1);
	wbx_activate_host(he, &r);
	((init_fn)proc(he, "Init"))();
	wbx_deactivate_host(he, &r);
	membuf junk = {0};
	wbx_save_state(he, mem_write, (uintptr_t)&junk, &r);
	CHECK(r.error_message[0] != 0);
	/* double seal -> error */
	wbx_seal(he, &r); CHECK(!r.error_message[0]);
	wbx_seal(he, &r); CHECK(r.error_message[0] != 0);
	/* missing proc -> 0, not an error */
	wbx_activate_host(he, &r);
	wbx_get_proc_addr(he, "NoSuchExport", &r);
	CHECK(!r.error_message[0] && r.data == 0);
	/* out-of-range callback slot -> error */
	wbx_get_callback_addr(he, log_cb, 999, &r);
	CHECK(r.error_message[0] != 0);
	wbx_deactivate_host(he, &r);
	wbx_destroy_host(he, &r);

	/* ---- corrupt-state rejection: flip the embedded ELF hash ---- */
	CHECK(state.len > 100);
	state.buf[60] ^= 0xFF;   /* somewhere inside the ElfLoader hash region */
	mb_host *hc = make_host(path, 0xABCD);
	wbx_activate_host(hc, &r); ((init_fn)proc(hc, "Init"))();
	wbx_deactivate_host(hc, &r); wbx_seal(hc, &r);
	memreader corrupt = { state.buf, state.len, 0 };
	wbx_load_state(hc, mem_reader, (uintptr_t)&corrupt, &r);
	CHECK(r.error_message[0] != 0);   /* corrupted state rejected */
	wbx_destroy_host(hc, &r);

	free(state.buf); free(junk.buf);

	/* ---- a guest that aborts says why, in the diagnostic log ---- */
	STAGE("checking that a guest abort is reported with its last words");
	CHECK(guest_abort_is_reported(argv[0], path));

	if (fails == 0) printf("run_guest: all checks passed\n");
	else printf("run_guest: %d checks FAILED\n", fails);
	return fails ? 1 : 0;
}
