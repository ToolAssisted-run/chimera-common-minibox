/* miniBox conformance guest - a minimal waterbox core proving the toolchain
 * (gcc + musl + emulibc + linkscript) and the host end to end. Not an emulator;
 * a deterministic integer "machine" whose whole state lives in savestated
 * memory, plus a sealed constant table, an invisible scratch buffer, a guest
 * heap allocation, a mounted-file read, and a host callback - so it exercises
 * every phase-1 mechanism. */
/* for syscall(): musl declares it only under _GNU_SOURCE, and this file is
 * compiled -std=c11 */
#define _GNU_SOURCE
#include <emulibc.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/mman.h>

/* Savestated state (plain globals -> .bss / savestated memory). */
static uint64_t g_acc;
static uint32_t g_step;
static uint8_t *g_heap;      /* malloc'd (sbrk) - savestated */

static uint32_t *g_table;    /* alloc_sealed - frozen after seal */
static uint32_t *g_scratch;  /* alloc_invisible - never savestated */

ECL_ENTRY void (*g_log_cb)(uint32_t value) = 0;
ECL_EXPORT void SetLogCallback(ECL_ENTRY void (*cb)(uint32_t)) { g_log_cb = cb; }

/* Reads an optional mounted "seed" file to prove the VFS + open/read syscalls. */
static uint32_t read_seed(void) {
	FILE *f = fopen("seed", "rb");
	if (!f) return 0x1234;
	uint32_t v = 0;
	fread(&v, 1, sizeof(v), f);
	fclose(f);
	return v;
}

/* A guest handing the host a path it must not follow.
 *
 * A guest may be broken, may be hostile, or may simply have a bug - mia calls
 * open(NULL) when it is hunting for a database it has not got - and none of
 * those may take the host down. Before this was guarded the host dereferenced
 * address zero inside its own libc and the process died with no diagnostic at
 * all: the sandbox killed by the thing it contains.
 *
 * Returns 1 when every one of them was refused and the guest is still here. */
static int bad_paths_are_refused(void) {
	if (open(NULL, O_RDONLY) >= 0) return 0;
	/* Not a pointer at all, and one just past the end of everything the guest
	 * owns - the host must not read either. */
	if (open((const char *)(uintptr_t)8, O_RDONLY) >= 0) return 0;
	if (open((const char *)~(uintptr_t)0, O_RDONLY) >= 0) return 0;
	struct stat st;
	if (stat(NULL, &st) >= 0) return 0;
	return 1;
}

/* The box has no /proc, and nothing mounted in it is a symlink.
 *
 * A core may still ask - RPCS3 does, twice, hunting for its own executable -
 * and asking must not stop the machine. Both answers are checked, because a
 * host that refused everything with a single errno would hide the difference
 * between a name that is not here and a name that is here and is not a link.
 *
 * Returns 1 when both were refused, for the right reason. */
static int readlinks_are_refused(void) {
	char buf[64];
	errno = 0;
	if (readlink("/proc/self/exe", buf, sizeof buf) >= 0) return 0;
	if (errno != ENOENT) return 0;
	errno = 0;
	if (readlink("seed", buf, sizeof buf) >= 0) return 0;   /* mounted, not a link */
	if (errno != EINVAL) return 0;
	return 1;
}

/* ---- calls that used to stop the machine (spec v2.2) ----
 * Each export below exercises one and returns 1 when the machine is still
 * alive afterwards with the specified answer. Before v2.2 every one of these
 * stopped the machine (unknown-syscall death, or a host fault for the NULL
 * clone area), so no working movie can depend on the old way. */

/* install accepted, never delivered */
ECL_EXPORT int SigactionAccepted(void) {
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGUSR1, &sa, NULL) != 0) return 0;
	/* the old action reads as the default, not as what was on the stack */
	struct sigaction old;
	memset(&old, 0xA5, sizeof old);
	if (sigaction(SIGUSR1, &sa, &old) != 0) return 0;
	if (old.sa_handler != SIG_DFL || old.sa_flags != 0) return 0;
	/* and a pointer the guest does not own is EFAULT, not a host fault */
	errno = 0;
	if (syscall(SYS_rt_sigaction, SIGUSR1, 0, (void *)16, 8) != -1 || errno != EFAULT) return 0;
	return 1;
}

/* no pipes in-guest: ENOSYS the caller must cope with */
ECL_EXPORT int PipeRefused(void) {
	int fds[2];
	errno = 0;
	if (pipe(fds) != -1) return 0;
	if (errno != ENOSYS) return 0;
	return 1;
}

/* zeros: no resource usage is observable in-guest */
ECL_EXPORT int GetrusageZeroed(void) {
	struct rusage ru;
	memset(&ru, 0xA5, sizeof ru);
	if (getrusage(RUSAGE_SELF, &ru) != 0) return 0;
	/* the kernel struct is 144 bytes; musl pads struct rusage with
	 * __reserved tail the kernel never touches, so only the first 144
	 * bytes are specified. */
	const unsigned char *p = (const unsigned char *)&ru;
	for (size_t i = 0; i < 144; i++) if (p[i] != 0) return 0;
	errno = 0;
	if (syscall(SYS_getrusage, RUSAGE_SELF, (void *)16) != -1 || errno != EFAULT) return 0;
	return 1;
}

/* pwrite through a descriptor that is not open: EBADF, and the machine goes
 * on. The call did not exist, so this was the end of the guest - which a
 * Triforce game writing its IC card to a file it had failed to open found out
 * (chimera issue #185). A buffer the guest does not own is EFAULT. */
ECL_EXPORT int PwriteBadDescriptor(void) {
	char sixteen[16];
	memset(sixteen, 0x5A, sizeof sixteen);
	errno = 0;
	if (pwrite(-1, sixteen, sizeof sixteen, 0) != -1 || errno != EBADF) return 0;
	errno = 0;
	if (syscall(SYS_pwrite64, 1, (void *)16, 8, 0) != -1 || errno != EFAULT) return 0;
	return 1;
}

/* no network in-guest: a socket is refused, and the machine goes on. The call
 * was not there, so asking was the end of the guest (chimera issue #184). */
ECL_EXPORT int SocketRefused(void) {
	errno = 0;
	if (syscall(SYS_socket, 2 /* AF_INET */, 1 /* SOCK_STREAM */, 0) != -1) return 0;
	if (errno != EAFNOSUPPORT) return 0;
	errno = 0;
	if (syscall(SYS_socket, 1 /* AF_UNIX */, 2 /* SOCK_DGRAM */, 0) != -1 || errno != EAFNOSUPPORT) return 0;
	return 1;
}

/* a NULL thread area is a foreign clone convention: EINVAL, not a fault */
ECL_EXPORT int NullCloneRefused(void) {
	errno = 0;
	if (syscall(2000, 0, 0, 0, 0, 0) != -1) return 0;   /* NR_wbx_clone */
	if (errno != EINVAL) return 0;
	return 1;
}

/* ---- spec v2 invariants a v3 host must preserve ----
 * This guest declares nothing, so every one of these must hold exactly as
 * the v2 spec says, on any host. */

/* the clock is the v2 constant, reads tick nothing */
ECL_EXPORT int V2ClockConstant(void) {
	struct timespec a, b;
	if (syscall(SYS_clock_gettime, 0, &a) != 0) return 0;
	if (syscall(SYS_clock_gettime, 0, &b) != 0) return 0;
	if (a.tv_sec != 1495889068 || a.tv_nsec != 0) return 0;
	if (b.tv_sec != a.tv_sec || b.tv_nsec != a.tv_nsec) return 0;
	return 1;
}

/* a timed wait with no waker never expires on its own: parked until woken */
static int v2_fut;
static long v2_wret;
static void *v2_waiter(void *arg) {
	(void)arg;
	struct timespec to = { 0, 100000000 };   /* 100 ms of a clock that never moves */
	v2_wret = syscall(SYS_futex, &v2_fut, 0 /*WAIT*/, 0, &to, NULL, 0);
	return 0;
}
ECL_EXPORT int V2TimedWaitIgnored(void) {
	pthread_t th;
	v2_wret = 0x5a5a5a5a;
	if (pthread_create(&th, 0, v2_waiter, 0) != 0) return 0;
	for (int i = 0; i < 5; i++) syscall(SYS_sched_yield);   /* no clock: nothing expires */
	if (syscall(SYS_futex, &v2_fut, 1 /*WAKE*/, 1, NULL, NULL, 0) != 1) return 0;
	pthread_join(th, 0);
	if (v2_wret != 0) return 0;   /* woken, never ETIMEDOUT */
	return 1;
}

/* mremap blocked from growing, without MAYMOVE, is EEXIST */
ECL_EXPORT int V2MremapBlocked(void) {
	uint8_t *p1 = (uint8_t *)syscall(SYS_mmap, 0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p1 == MAP_FAILED) return 0;
	uint8_t *fill = (uint8_t *)syscall(SYS_mmap, p1 + 8192, 8192, PROT_READ | PROT_WRITE,
	                                   MAP_PRIVATE | MAP_ANONYMOUS | 0x100000 /*NOREPLACE*/, -1, 0);
	if (fill == MAP_FAILED && errno != EEXIST) return 0;
	(void)fill;
	errno = 0;
	if (syscall(SYS_mremap, p1, 8192, 16384, 0) != -1 || errno != 17 /*EEXIST*/) return 0;
	return 1;
}

ECL_EXPORT int Init(void) {
	if (!bad_paths_are_refused()) return 0;
	if (!readlinks_are_refused()) return 0;
	g_table = (uint32_t *)alloc_sealed(256 * sizeof(uint32_t));
	if (!g_table) return 0;
	uint32_t seed = read_seed();
	for (int i = 0; i < 256; i++) g_table[i] = (uint32_t)((i + seed) * 2654435761u);
	g_scratch = (uint32_t *)alloc_invisible(1024 * sizeof(uint32_t));
	if (!g_scratch) return 0;
	g_heap = (uint8_t *)malloc(4096);   /* exercises brk/sbrk */
	if (!g_heap) return 0;
	memset(g_heap, 0, 4096);

	/* A big allocation takes musl past its mmap threshold, so this exercises
	 * mmap(NULL, ...) - the host picking an address and handing it back. That
	 * path returned a 32-bit-truncated address on Windows and nothing caught it,
	 * because every guest here only ever grew the heap with brk. Writing to the
	 * memory is the point: a truncated address faults immediately. */
	{
		const size_t big_size = 300u * 1024u;
		uint8_t *big = (uint8_t *)malloc(big_size);
		if (!big) return 0;
		memset(big, 0xA5, big_size);
		if (big[0] != 0xA5 || big[big_size - 1] != 0xA5) return 0;
		free(big);
	}
	/* The CPU mask, both ways round, by raw syscall so this asks the host exactly
	 * what a real guest asks it. Reading it has always worked; SETTING it was
	 * missing, and a missing syscall is not a refusal the caller can handle - the
	 * host aborts the guest where it stands. Mesa asks for both during thread
	 * setup, so from the day a core linked Mesa this killed it mid-frame, with
	 * "unimplemented syscall 203" and a core dump, intermittently enough to look
	 * like flaky CI. Nothing here checks WHICH cpus come back: the host is
	 * entitled to say "one", and does. */
	{
		unsigned char mask[128];
		const long got = syscall(SYS_sched_getaffinity, 0, sizeof(mask), mask);
		if (got <= 0) return 0;
		if (syscall(SYS_sched_setaffinity, 0, (size_t)got, mask) != 0) return 0;
	}
	/* Flushing, the same way round: raw syscalls, because a missing one killed
	 * RPCS3 on its first save ("unimplemented syscall 162", chimera #75). There
	 * is nothing to flush in a machine whose files are memory, so the only thing
	 * that may differ is a descriptor that is not open. */
	{
		if (syscall(SYS_sync) != 0) return 0;
		if (syscall(SYS_fsync, 2) != 0) return 0;
		if (syscall(SYS_fdatasync, 2) != 0) return 0;
		if (syscall(SYS_syncfs, 2) != 0) return 0;
		if (syscall(SYS_fsync, 999) != -1) return 0;
	}
	/* Error numbers are LINUX numbers, whatever the host's libc spells: a
	 * Windows host handed its own MSVCRT values through, ENOSYS as 40 (which
	 * this guest's musl reads as ELOOP) and EOPNOTSUPP as 130. Two the host
	 * gives on purpose: set_thread_area is musl's business, and a file-backed
	 * mmap is not supported. */
	{
		errno = 0;
#if defined(__aarch64__)
		/* on aarch64 it is how musl sets its thread pointer (the host keeps
		 * TPIDR_EL0); a null one is refused and the live one stays */
		if (syscall(SYS_set_thread_area, 0) != -1 || errno != EINVAL) return 0;
#elif defined(__x86_64__)
		if (syscall(SYS_set_thread_area, 0) != -1 || errno != ENOSYS) return 0;
#else
#error "miniBox runs on x86-64 and aarch64 only"
#endif
		errno = 0;
		if (syscall(SYS_mmap, 0, 4096, PROT_READ, MAP_PRIVATE, 3, 0) != -1 || errno != EOPNOTSUPP) return 0;
	}

	g_acc = seed;
	g_step = 0;
	fprintf(stderr, "conformance guest: Init done (seed=%08x)\n", seed);
	return 1;
}

ECL_EXPORT uint32_t Step(uint32_t input) {
	for (int i = 0; i < 1024; i++) g_scratch[i] = input ^ g_table[(input + i) & 0xFF];
	uint32_t mixed = 0;
	for (int i = 0; i < 1024; i++) mixed += g_scratch[i];
	g_heap[g_step & 0xFFF] ^= (uint8_t)mixed;   /* touch the heap (savestated) */
	g_acc += (uint64_t)mixed * (g_step + 1) + g_heap[g_step & 0xFFF];
	g_step++;
	if (g_log_cb) g_log_cb((uint32_t)g_acc);
	return (uint32_t)g_acc;
}

ECL_EXPORT uint64_t GetAcc(void) { return g_acc; }
ECL_EXPORT uint32_t GetStep(void) { return g_step; }

/* Dies the way a panicking or out-of-memory guest dies: says something on its
 * stderr, then abort() - which musl turns into tkill(self, SIGABRT). The host
 * must put both into its diagnostic log, since a GUI process has no stderr to
 * show either (run_guest --abort-child). */
ECL_EXPORT void Abort(void) {
	fprintf(stderr, "conformance guest: these are my last words\n");
	abort();
}

/* What the guest finds in r10 where the host hands control back: on entering an
 * export, and straight after a syscall returns. The host must leave nothing of
 * its own there - it used to leave &mb_host.context, which a guest that spills a
 * scratch register carried into its savestates (run_guest checks both read 0).
 * Assembly, because a compiler owns r10 at every other point. brk(0) is the
 * syscall: it only reads, and the host always implements it. */
#if defined(__aarch64__)
/* aarch64: no single register carries the context. What a guest could find
 * of the host is any scratch register that is neither an argument nor the
 * answer, so each probe returns them all OR-ed together: x8-x18 on entry
 * (x10 is the export's own address, a guest one, and left out), x1-x18 after
 * a syscall and after a callback. */
#define WBX_OR_SCRATCH(first) \
	"\tmov x0, " first "\n" \
	"\torr x0, x0, x9\n\torr x0, x0, x11\n\torr x0, x0, x12\n\torr x0, x0, x13\n" \
	"\torr x0, x0, x14\n\torr x0, x0, x15\n\torr x0, x0, x16\n\torr x0, x0, x17\n\torr x0, x0, x18\n"
__asm__(
	".text\n"
	".globl EntryR10\n.type EntryR10,%function\n"
	"EntryR10:\n"
	WBX_OR_SCRATCH("x8")
	"\tret\n"
	".globl SyscallR10\n.type SyscallR10,%function\n"
	"SyscallR10:\n"
	"\tstp x29, x30, [sp, #-16]!\n"
	"\tmov x0, #0\n"
	"\tmov x8, #12\n"
	"\tmovz x16, #0x0080\n"
	"\tmovk x16, #0x035f, lsl #32\n"
	"\tblr x16\n"
	"\torr x8, x8, x1\n\torr x8, x8, x2\n\torr x8, x8, x3\n\torr x8, x8, x4\n"
	"\torr x8, x8, x5\n\torr x8, x8, x6\n\torr x8, x8, x7\n\torr x8, x8, x10\n"
	WBX_OR_SCRATCH("x8")
	"\tldp x29, x30, [sp], #16\n"
	"\tret\n"
	".globl ExtcallR10\n.type ExtcallR10,%function\n"
	"ExtcallR10:\n"
	"\tstp x29, x30, [sp, #-16]!\n"
	"\tadrp x1, g_log_cb\n"
	"\tldr x1, [x1, #:lo12:g_log_cb]\n"
	"\tcbz x1, 1f\n"
	"\tmov x0, #0\n"
	"\tblr x1\n"
	"1:\n"
	"\torr x8, x8, x1\n\torr x8, x8, x2\n\torr x8, x8, x3\n\torr x8, x8, x4\n"
	"\torr x8, x8, x5\n\torr x8, x8, x6\n\torr x8, x8, x7\n\torr x8, x8, x10\n"
	WBX_OR_SCRATCH("x8")
	"\tldp x29, x30, [sp], #16\n"
	"\tret\n");
#elif defined(__x86_64__)
__asm__(
	".text\n"
	".globl EntryR10\n.type EntryR10,@function\n"
	"EntryR10:\n"
	"\tmov %r10, %rax\n"
	"\tret\n"
	".globl SyscallR10\n.type SyscallR10,@function\n"
	"SyscallR10:\n"
	"\tpush %rbx\n"
	"\txor %edi, %edi\n"
	"\tmov $12, %eax\n"
	"\tmovabs $0x35f00000080, %r10\n"
	"\tcall *%r10\n"
	"\tmov %r10, %rax\n"
	"\tpop %rbx\n"
	"\tret\n"
	/* And the third boundary: a guest calling OUT to a host callback comes back
	 * through the blob's extcall path. That return used to leave the context in
	 * r10 and the host callback's own scratch registers - stack addresses among
	 * them - for the guest to spill. Calls the log callback the host registered. */
	".globl ExtcallR10\n.type ExtcallR10,@function\n"
	"ExtcallR10:\n"
	"\tpush %rbx\n"
	"\tmov g_log_cb(%rip), %rax\n"
	"\ttest %rax, %rax\n"
	"\tjz 1f\n"
	"\txor %edi, %edi\n"
	"\tcall *%rax\n"
	"1:\n"
	"\tmov %r10, %rax\n"
	"\tpop %rbx\n"
	"\tret\n");
#else
#error "miniBox runs on x86-64 and aarch64 only"
#endif

/* Faults with rsp pointing into a guard page: a heap page is protected to
 * PROT_NONE, rsp is pointed into it, and ud2 faults. The death report must
 * complete without a nested fault - both stack readers check page
 * readability first (run_guest checks the report; the process surviving
 * with the machine refused is the check). Page protections are per-page
 * state, so the runner's load_state after the death puts the page back. */
static uint8_t guard_area[8192] __attribute__((aligned(4096)));
ECL_EXPORT void GuardFault(void) {
	uintptr_t base = ((uintptr_t)guard_area + 0xFFF) & ~(uintptr_t)0xFFF;
	if (mprotect((void *)base, 4096, PROT_NONE) != 0) return;
#if defined(__aarch64__)
	__asm__ volatile ("mov sp, %0\n\tudf #0" :: "r" (base + 2048) : "memory");
#elif defined(__x86_64__)
	__asm__ volatile ("mov %0, %%rsp\n\tud2" :: "r" (base + 2048) : "memory");
#else
#error "miniBox runs on x86-64 and aarch64 only"
#endif
	__builtin_unreachable();
}

/* ---- ways a guest dies ----
 * Each export below ends the machine a different way. The host must hand
 * control back to the caller, say why, refuse every later call, and bring the
 * machine back when a state is loaded (run_guest, "a guest that dies"). */
ECL_EXPORT uint32_t Alive(void) { return 0xA11FE; }

/* Memory the machine has not touched before, written: a megabyte through
 * musl's mmap path. On a host out of memory that is where the commit is
 * refused (run_guest: out_of_memory_is_said). */
ECL_EXPORT uint32_t TouchFresh(void) {
	const size_t size = 1u << 20;
	/* volatile, a write per page: a memset of memory freed right after is a
	 * dead store the compiler removes, and then nothing is touched at all */
	volatile uint8_t *fresh = (volatile uint8_t *)malloc(size);
	if (!fresh) return 0;
	for (size_t i = 0; i < size; i += 4096) fresh[i] = 0x5A;
	uint32_t ok = 0xF4E5;
	for (size_t i = 0; i < size; i += 4096) if (fresh[i] != 0x5A) ok = 0;
	free((void *)fresh);
	return ok;
}

ECL_EXPORT void ExitNow(void) { exit(7); }   /* exit_group, after musl's atexit work */


/* writes to an address no region of the machine covers */
ECL_EXPORT void WildWrite(void) {
	volatile uintptr_t where = 0x10;
	*(volatile uint32_t *)where = 1;
}

/* Instructions the compiler would not emit on request. Halt is exactly musl's
 * a_crash(), which its allocator runs when its own heap check fails. */
#if defined(__aarch64__)
/* aarch64: Halt is musl's a_crash() there (udf #0xf4), Ud2 a plain undefined
 * instruction. There is no DivideByZero: an aarch64 integer division by zero
 * answers 0 rather than trapping. FsProbe and ClobberAndProbe are x86-64's
 * (a dropped %fs base); TPIDR_EL0 is never dropped. */
__asm__(
	".text\n"
	".globl Halt\n.type Halt,%function\n"
	"Halt:\n"
	"\tudf #0xf4\n"
	"\tret\n"
	".globl Ud2\n.type Ud2,%function\n"
	"Ud2:\n"
	"\tudf #0\n"
	"\tret\n"
	".globl UnknownSyscall\n.type UnknownSyscall,%function\n"
	"UnknownSyscall:\n"
	"\tstp x29, x30, [sp, #-16]!\n"
	"\tmov x0, #1\n"
	"\tmov x1, #2\n"
	"\tmov x2, #3\n"
	"\tmov x8, #4242\n"
	"\tmovz x16, #0x0080\n"
	"\tmovk x16, #0x035f, lsl #32\n"
	"\tblr x16\n"
	"\tldp x29, x30, [sp], #16\n"
	"\tret\n"
	".local deadlock_word\n.comm deadlock_word,4,4\n"
	".globl Deadlock\n.type Deadlock,%function\n"
	"Deadlock:\n"
	"\tstp x29, x30, [sp, #-16]!\n"
	"\tadrp x0, deadlock_word\n"
	"\tadd x0, x0, #:lo12:deadlock_word\n"
	"\tmov x1, #0\n"
	"\tmov x2, #0\n"
	"\tmov x3, #0\n"
	"\tmov x8, #202\n"
	"\tmovz x16, #0x0080\n"
	"\tmovk x16, #0x035f, lsl #32\n"
	"\tblr x16\n"
	"\tldp x29, x30, [sp], #16\n"
	"\tret\n");
#elif defined(__x86_64__)
__asm__(
	".text\n"
	".globl Halt\n.type Halt,@function\n"
	"Halt:\n"
	"\thlt\n"
	"\tret\n"
	".globl Ud2\n.type Ud2,@function\n"
	"Ud2:\n"
	"\tud2\n"
	"\tret\n"
	".globl DivideByZero\n.type DivideByZero,@function\n"
	"DivideByZero:\n"
	"\tmov $1, %eax\n"
	"\txor %edx, %edx\n"
	"\txor %ecx, %ecx\n"
	"\tdiv %ecx\n"
	"\tret\n"
	/* %fs:0 through whatever base is loaded: with the base dropped (what
	 * Windows does at a scheduler quantum) this faults, the host reinstalls
	 * the live thread pointer and retries, and the same value comes back. */
	".globl FsProbe\n.type FsProbe,@function\n"
	"FsProbe:\n"
	"\tmov %fs:0, %rax\n"
	"\tret\n"
	/* The drop and the access in one guest call, with no boundary between:
	 * the entry parked the host's base, so the fault below carries a valid
	 * parked value to check against - exactly a quantum drop mid-guest. */
	".globl ClobberAndProbe\n.type ClobberAndProbe,@function\n"
	"ClobberAndProbe:\n"
	"\txor %eax, %eax\n"
	"\twrfsbase %rax\n"
	"\tmov %fs:0, %rax\n"
	"\tret\n"
	/* straight into the host's syscall entry, as SyscallR10 does: libc's
	 * syscall() is not the thing under test here */
	".globl UnknownSyscall\n.type UnknownSyscall,@function\n"
	"UnknownSyscall:\n"
	"\tpush %rbx\n"
	"\tmov $1, %edi\n"
	"\tmov $2, %esi\n"
	"\tmov $3, %edx\n"
	"\tmov $4242, %eax\n"
	"\tmovabs $0x35f00000080, %r10\n"
	"\tcall *%r10\n"
	"\tpop %rbx\n"
	"\tret\n"
	/* FUTEX_WAIT on a word that holds the value waited for, with no other
	 * thread to wake it */
	".local deadlock_word\n.comm deadlock_word,4,4\n"
	".globl Deadlock\n.type Deadlock,@function\n"
	"Deadlock:\n"
	"\tpush %rbx\n"
	"\tlea deadlock_word(%rip), %rdi\n"
	"\txor %esi, %esi\n"
	"\txor %edx, %edx\n"
	"\txor %ecx, %ecx\n"
	"\tmov $202, %eax\n"
	"\tmovabs $0x35f00000080, %r10\n"
	"\tcall *%r10\n"
	"\tpop %rbx\n"
	"\tret\n");
#else
#error "miniBox runs on x86-64 and aarch64 only"
#endif

int main(void) { return 0; }
