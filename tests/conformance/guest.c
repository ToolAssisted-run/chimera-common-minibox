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
#include <sys/syscall.h>

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

/* ---- ways a guest dies ----
 * Each export below ends the machine a different way. The host must hand
 * control back to the caller, say why, refuse every later call, and bring the
 * machine back when a state is loaded (run_guest, "a guest that dies"). */
ECL_EXPORT uint32_t Alive(void) { return 0xA11FE; }

ECL_EXPORT void ExitNow(void) { exit(7); }   /* exit_group, after musl's atexit work */


/* writes to an address no region of the machine covers */
ECL_EXPORT void WildWrite(void) {
	volatile uintptr_t where = 0x10;
	*(volatile uint32_t *)where = 1;
}

/* Instructions the compiler would not emit on request. Halt is exactly musl's
 * a_crash(), which its allocator runs when its own heap check fails. */
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

int main(void) { return 0; }
