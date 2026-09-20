/* Host<->guest transitions. Maps the fixed interop blob (interop.bin, assembled
 * from BizHawk waterboxhost src/context/interop.s) at MB_ORG and drives entries through it.
 * Faithful C port of BizHawk waterboxhost src/context/{mod.rs,thunks.rs} (Linux path). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "minibox_internal.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifndef _WIN32
#include <sys/syscall.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/auxv.h>
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#define CALL_GUEST_SIMPLE_ADDR (MB_ORG + 0x100)
#define CALL_GUEST_IMPL_ADDR   (MB_ORG + 0x200)
#define EXTCALL_THUNK_ADDR     (MB_ORG + 0x300)
#define RUNTIME_TABLE_ADDR     (MB_ORG + 0x800)

/* guarded.S reads the context by offset; any change to mb_context must move these */
_Static_assert(offsetof(mb_context, thread_area) == 0x000, "guarded.S CTX_THREAD_AREA");
_Static_assert(offsetof(mb_context, host_rsp) == 0x008, "guarded.S CTX_HOST_RSP");
_Static_assert(offsetof(mb_context, guest_rsp) == 0x010, "guarded.S CTX_GUEST_RSP");
_Static_assert(offsetof(mb_context, host_rsp_alt) == 0x018, "guarded.S CTX_HOST_RSP_ALT");
_Static_assert(offsetof(mb_context, guest_rsp_alt) == 0x020, "guarded.S CTX_GUEST_RSP_ALT");
_Static_assert(offsetof(mb_context, host_fs) == 0x238, "guarded.S CTX_HOST_FS");
_Static_assert(offsetof(mb_context, fs_swap) == 0x240, "guarded.S CTX_FS_SWAP");
_Static_assert(offsetof(mb_context, dead) == 0x241, "guarded.S CTX_DEAD");
_Static_assert(offsetof(mb_context, esc_rsp) == 0x248, "guarded.S CTX_ESC_RSP");
_Static_assert(offsetof(mb_context, calls) == 0x250, "guarded.S CTX_CALLS");
_Static_assert(MB_ORG + 0x200 == 0x35f00000200ull, "guarded.S CALL_GUEST_IMPL");

/* interop.bin lives in the sibling reference tree; embedded at build time. */
extern const unsigned char mb_interop_bin[];
extern const unsigned int  mb_interop_bin_len;

static bool g_interop_ready = false;

static void init_interop_area(void) {
	if (g_interop_ready) return;
	mb_range want = { MB_ORG, mb_interop_bin_len };
	mb_range got;
	if (mb_pal_map_anon(mb_range_align_expand(want), MB_PROT_RW, &got) != 0) {
		fprintf(stderr, "miniBox: failed to map interop area at %llx\n", (unsigned long long)MB_ORG);
		abort();
	}
	memcpy((void *)MB_ORG, mb_interop_bin, mb_interop_bin_len);
	mb_pal_protect(mb_range_align_expand(want), MB_PROT_RX);
#ifdef _WIN32
	/* register the hand-written unwind info so host SEH can unwind across the
	 * guest stack-switch (the table lives at RUNTIME_TABLE_ADDR in interop.bin) */
	if (!RtlAddFunctionTable((PRUNTIME_FUNCTION)RUNTIME_TABLE_ADDR, 2, MB_ORG)) {
		fprintf(stderr, "miniBox: RtlAddFunctionTable failed\n");
		abort();
	}
#endif
	g_interop_ready = true;
}

#ifndef _WIN32
/* Per-host-thread mini-TLS block reached via [gs:0x18] (index 3). Windows uses
 * the TEB's SubSystemTib field at gs:0x18 directly, so no setup is needed. */
static __thread uintptr_t g_tib[4];
#endif


void mb_prepare_thread(void) {
	init_interop_area();
#ifndef _WIN32
	uintptr_t gs = 0;
	if (syscall(SYS_arch_prctl, 0x1004 /*ARCH_GET_GS*/, &gs) == 0 && gs == 0) {
		syscall(SYS_arch_prctl, 0x1001 /*ARCH_SET_GS*/, (uintptr_t)&g_tib[0]);
	}
#endif
}

#ifdef MB_HAVE_FSBASE
/* A thread pointer for the guest's first instructions.
 *
 * The guest only gets its own %fs once musl has built its TLS block and called
 * __set_thread_area - but musl's own startup reaches for a thread local before
 * that, and so does anything the compiler inlined ahead of it. Until then %fs
 * is whatever the host left there, and what the host leaves there differs:
 * on Linux it is glibc's TCB, so the reads land on real memory and the guest
 * gets away with nonsense; on Windows nothing uses %fs and its base is 0, so
 * the first thread-local read dereferences -8 and the guest is dead before it
 * can install the pointer that would have saved it.
 *
 * So it starts with one: a zeroed host page, pointed at from the middle so
 * that the negative offsets a TLS block uses stay inside it. Nothing durable
 * lives here - musl overwrites thread_area with the real block within the
 * first call - and it is never read again afterwards. */
uintptr_t mb_early_tp = 0;   /* the audit knows to forgive this one */
static uintptr_t mb_early_thread_pointer(void) {
	uintptr_t p = mb_early_tp;
	if (p == 0) {
		mb_range want = { 0, MB_PAGESIZE * 2 }, got;
		if (mb_pal_map_anon(want, MB_PROT_RW, &got) == 0)
			p = mb_early_tp = got.start + MB_PAGESIZE;
	}
	return p;
}
#endif

void mb_context_init(mb_context *c, uintptr_t guest_rsp, uintptr_t guest_rsp_alt, mb_syscall_cb dispatch) {
	memset(c, 0, sizeof(*c));
	c->guest_rsp = guest_rsp;
	c->guest_rsp_alt = guest_rsp_alt;
	c->dispatch_syscall = dispatch;
#ifdef MB_HAVE_FSBASE
	/* Replaced by the guest's own the moment musl installs it. */
	c->thread_area = mb_early_thread_pointer();
#endif
}

typedef uintptr_t (MB_SYSV *call_guest_simple_fn)(uintptr_t entry, mb_context *c);

#ifdef MB_HAVE_FSBASE
/* Whether %fs swapping is on, as a PLAIN GLOBAL. The syscall dispatcher has to
 * restore the host's %fs as its very first instruction - it is entered with the
 * guest's %fs, and any libc call made before the swap (getenv, even one that
 * only reads errno) would run against guest TLS and corrupt it. So the decision
 * cannot involve a function call there; it is made once, here, in host context. */
bool mb_fs_swap = false;
mb_context *mb_guest_ctx = NULL;

/* Does the OS let userspace use rdfsbase/wrfsbase? They fault when it does not,
 * so this is asked once and never guessed. Each platform is asked the way it
 * documents: Linux advertises it in AT_HWCAP2, Windows answers
 * IsProcessorFeaturePresent. A fault probe would be at the mercy of whatever
 * debugger happens to intercept the signal first. */
#ifdef _WIN32
#ifndef PF_RDWRFSGSBASE_AVAILABLE
#define PF_RDWRFSGSBASE_AVAILABLE 22
#endif
bool mb_fsbase_ok(void) {
	static int cached = -1;
	if (cached >= 0) return cached != 0;
	cached = IsProcessorFeaturePresent(PF_RDWRFSGSBASE_AVAILABLE) ? 1 : 0;
	if (!cached && getenv("MB_FORCE_FS_SWAP")) cached = 1;  /* testing only */
	mb_fs_swap = cached != 0;
	return cached != 0;
}
#else
#ifndef HWCAP2_FSGSBASE
#define HWCAP2_FSGSBASE (1u << 1)
#endif
bool mb_fsbase_ok(void) {
	static int cached = -1;
	if (cached >= 0) return cached != 0;
	cached = (getauxval(AT_HWCAP2) & HWCAP2_FSGSBASE) != 0;
	if (!cached && getenv("MB_FORCE_FS_SWAP")) cached = 1;  /* testing only */
	mb_fs_swap = cached != 0;
	return cached != 0;
}
#endif
#endif

uintptr_t mb_call_guest_simple(uintptr_t entry, mb_context *c) {
	call_guest_simple_fn f = (call_guest_simple_fn)CALL_GUEST_SIMPLE_ADDR;
	/* the context the fault handlers judge a fault against is the one running
	 * now - for every guest, as the entry thunks set it */
	mb_guest_ctx = c;
#ifdef MB_HAVE_FSBASE
	/* Guest code may use %fs-direct TLS (Rust does); give it its own thread
	 * pointer and put the host's %fs back afterwards. On the very first entry
	 * (_start) thread_area is still 0 - musl sets it during that call - so
	 * leave %fs alone until it exists; the guest uses %gs until then. */
	if (c->fs_swap) {
		c->host_fs = mb_rdfsbase();
		mb_guest_ctx = c;
		if (c->thread_area) mb_wrfsbase(c->thread_area);
		uintptr_t r = f(entry, c);
		mb_wrfsbase(c->host_fs);
		return r;
	}
#endif
	return f(entry, c);
}

uintptr_t mb_get_callback_ptr(uintptr_t slot) {
	return EXTCALL_THUNK_ADDR + slot * 16;
}

/* ---- thunk manager (thunks.rs) ---- */
/* 32 was enough for the bare stack-switch jump; the %fs swap a Rust guest needs
 * (see mb_thunks_get) brings one thunk to 71 bytes.
 *
 * ONE PAGE WAS NOT ENOUGH. A page holds 32 thunks, shared between entry points
 * and extcall wrappers, and a core with the full optional tooling wants more
 * than that: quickerNES asks for 45 and silently got 32 - mb_thunks_get
 * answered 0 for the rest, which mb_host_proc_addr reports exactly the way it
 * reports a symbol that is not there, so the host read a full pool as "this
 * core exports no trace logger and no save data". Found 2026-09-20 building
 * Chimera's memory callbacks, which were the exports that fell off the end.
 *
 * 16 pages is 512 thunks, which is 64 KiB of address space per instance and
 * more than any core has exports. And exhaustion is no longer silent. */
#define THUNK_SIZE 128
#define THUNK_ARENA (16u * MB_PAGESIZE)
#define THUNK_CAP (THUNK_ARENA / THUNK_SIZE)
struct mb_thunks {
	mb_range mem;
	uintptr_t entries[THUNK_CAP];
	uintptr_t ptrs[THUNK_CAP];
	size_t count;
	/* callbacks pointing the other way (guest -> host) get their own wrappers */
	uintptr_t ext_entries[THUNK_CAP];
	uintptr_t ext_ptrs[THUNK_CAP];
	size_t ext_count;
};

mb_thunks *mb_thunks_new(void) {
	mb_thunks *t = (mb_thunks *)calloc(1, sizeof(mb_thunks));
	mb_range in = { 0, THUNK_ARENA };
	if (mb_pal_map_anon(in, MB_PROT_RWX, &t->mem) != 0) { free(t); return NULL; }
	return t;
}

void mb_thunks_free(mb_thunks *t) {
	if (!t) return;
	mb_pal_unmap_anon(t->mem);
	free(t);
}

static void emit8(uint8_t **p, uint8_t v) { *(*p)++ = v; }
static void emit32(uint8_t **p, uint32_t v) { memcpy(*p, &v, 4); *p += 4; }
static void emit64(uint8_t **p, uintptr_t v) { memcpy(*p, &v, 8); *p += 8; }

uintptr_t mb_thunks_get(mb_thunks *t, uintptr_t guest_entry, mb_context *c) {
	for (size_t i = 0; i < t->count; i++)
		if (t->entries[i] == guest_entry) return t->ptrs[i];
	if ((t->count + t->ext_count + 1) * THUNK_SIZE > t->mem.size) {
		/* Never silently: a full pool used to be indistinguishable from an
		 * export that is not there, and a host read it as a core with no
		 * tooling. Say it once, loudly, naming the number. */
		static bool said = false;
		if (!said) { said = true; fprintf(stderr,
			"miniBox: the thunk pool is full (%zu entry points + %zu callbacks, cap %u) - "
			"further exports cannot be called and will look absent\n",
			t->count, t->ext_count, (unsigned)THUNK_CAP); }
		return 0;
	}
	uintptr_t addr = t->mem.start + t->count * THUNK_SIZE;
	uint8_t *p = (uint8_t *)addr;
	/* The thunk only says which call this is. Everything a call needs - the %fs
	 * swap a Rust guest wants, the escape record a guest that dies returns
	 * through - is one routine in guarded.S, entered with r10 = context and
	 * r11 = the guest function, the arguments untouched. The context also goes
	 * where the fault handlers read it: to repair %fs, and to find that record. */
	emit8(&p, 0x49); emit8(&p, 0xba); emit64(&p, (uintptr_t)c);            /* mov r10, ctx */
	emit8(&p, 0x49); emit8(&p, 0xbb); emit64(&p, guest_entry);              /* mov r11, entry */
	emit8(&p, 0x4c); emit8(&p, 0x89); emit8(&p, 0xd0);                      /* mov rax, r10 */
	emit8(&p, 0x48); emit8(&p, 0xa3); emit64(&p, (uintptr_t)&mb_guest_ctx); /* mov [abs], rax */
	emit8(&p, 0x48); emit8(&p, 0xb8); emit64(&p, (uintptr_t)&mb_guarded_call); /* mov rax, guarded */
	emit8(&p, 0xff); emit8(&p, 0xe0);                                       /* jmp rax */
	if ((size_t)(p - (uint8_t *)addr) > THUNK_SIZE) {
		/* Silent overflow here writes over the NEXT thunk, which shows up much
		 * later as a call into the middle of an instruction. */
		fprintf(stderr, "miniBox: thunk of %zu bytes does not fit THUNK_SIZE %d\n",
		        (size_t)(p - (uint8_t *)addr), THUNK_SIZE);
		abort();
	}
	t->entries[t->count] = guest_entry;
	t->ptrs[t->count] = addr;
	t->count++;
	return addr;
}


/* The mirror image of mb_thunks_get, for the other direction.
 *
 * A guest calling out to the host arrives through the interop blob, which
 * switches stacks but knows nothing about %fs - so the host's callback would
 * run with the GUEST's thread pointer still loaded. With a C guest that is
 * invisible (it uses %gs); with a Rust one, every host function that touches a
 * thread local - errno, a driver's context, anything in glibc - reads and
 * writes the guest's TLS block instead of its own. It survives only as long as
 * the callback does nothing real, which stops being true the moment the host
 * end drives a GPU.
 *
 * So the callback the guest is handed is not the host's function but this
 * wrapper: put the host's %fs back (the entry thunk parked it in ctx->host_fs
 * on the way in), call, and restore the guest's on the way out. It has to be
 * instructions rather than C for the same reason the syscall dispatcher does:
 * anything that runs before the swap runs on the wrong TLS.
 */
uintptr_t mb_thunks_get_extcall(mb_thunks *t, uintptr_t cb, mb_context *c) {
#ifdef MB_HAVE_FSBASE
	if (!c->fs_swap) return cb;
	for (size_t i = 0; i < t->ext_count; i++)
		if (t->ext_entries[i] == cb) return t->ext_ptrs[i];
	/* Entry thunks grow from the bottom of the page and these from the top,
	 * so a thunk taken out later cannot land on a wrapper handed out earlier
	 * (which is what happens if both count from the same end). */
	if ((t->count + t->ext_count + 1) * THUNK_SIZE > t->mem.size) {
		static bool said = false;
		if (!said) { said = true; fprintf(stderr,
			"miniBox: the thunk pool is full (%zu entry points + %zu callbacks, cap %u) - "
			"this callback cannot be given to the guest\n",
			t->count, t->ext_count, (unsigned)THUNK_CAP); }
		return 0;
	}
	uintptr_t addr = t->mem.start + t->mem.size - (t->ext_count + 1) * THUNK_SIZE;
	uint8_t *p = (uint8_t *)addr;
	/* The guest's %fs is read back from the context on the way out rather than
	 * saved from the register on the way in: the context is the live answer,
	 * and a host that lost the base while the callback ran (Windows drops it
	 * across a fault, and a GL callback takes plenty) would otherwise have the
	 * loss faithfully restored. Stack: entry rsp%16==8, push -> 0, call -> the
	 * callee sees 8. r10 is caller-saved, hence the push rather than a reload. */
	emit8(&p, 0x49); emit8(&p, 0xba); emit64(&p, (uintptr_t)c);        /* mov r10, ctx */
	emit8(&p, 0x41); emit8(&p, 0x52);                                  /* push r10 */
	emit8(&p, 0x49); emit8(&p, 0x8b); emit8(&p, 0x82);
	emit32(&p, (uint32_t)offsetof(mb_context, host_fs));               /* mov rax, [r10+host_fs] */
	emit8(&p, 0xf3); emit8(&p, 0x48); emit8(&p, 0x0f); emit8(&p, 0xae); emit8(&p, 0xd0); /* wrfsbase rax */
	emit8(&p, 0x48); emit8(&p, 0xb8); emit64(&p, cb);                  /* mov rax, cb */
	emit8(&p, 0xff); emit8(&p, 0xd0);                                  /* call rax */
	emit8(&p, 0x49); emit8(&p, 0x89); emit8(&p, 0xc3);                 /* mov r11, rax */
	emit8(&p, 0x41); emit8(&p, 0x5a);                                  /* pop r10 */
	emit8(&p, 0x49); emit8(&p, 0x8b); emit8(&p, 0x02);                 /* mov rax, [r10] (thread_area, live) */
	emit8(&p, 0xf3); emit8(&p, 0x48); emit8(&p, 0x0f); emit8(&p, 0xae); emit8(&p, 0xd0); /* wrfsbase rax */
	emit8(&p, 0x4c); emit8(&p, 0x89); emit8(&p, 0xd8);                 /* mov rax, r11 */
	emit8(&p, 0xc3);                                                   /* ret */
	t->ext_entries[t->ext_count] = cb;
	t->ext_ptrs[t->ext_count] = addr;
	t->ext_count++;
	return addr;
#else
	(void)t; (void)c;
	return cb;
#endif
}
