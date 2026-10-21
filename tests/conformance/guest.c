/* miniBox conformance guest - a minimal waterbox core proving the toolchain
 * (gcc + musl + emulibc + linkscript) and the host end to end. Not an emulator;
 * a deterministic integer "machine" whose whole state lives in savestated
 * memory, plus a sealed constant table, an invisible scratch buffer, a guest
 * heap allocation, a mounted-file read, and a host callback - so it exercises
 * every phase-1 mechanism. */
/* for syscall(): musl declares it only under _GNU_SOURCE, and this file is
 * compiled -std=c11 */
#define _GNU_SOURCE
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
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
#include <sys/random.h>
#include <sys/uio.h>

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

/* What a core reads back from rt_sigprocmask and ioctl is written: an empty
 * old mask, a zero window size, nothing waiting (2026-10-18). Both answered
 * "done" and wrote nothing, so a core read what was on its stack. */
ECL_EXPORT int AnswersAreWritten(void) {
	sigset_t old;
	memset(&old, 0xA5, sizeof old);
	sigset_t block;
	sigemptyset(&block);
	sigaddset(&block, SIGUSR1);
	if (syscall(SYS_rt_sigprocmask, SIG_BLOCK, &block, &old, 8) != 0) return 0;
	const uint8_t *bytes = (const uint8_t *)&old;
	for (int i = 0; i < 8; i++) if (bytes[i] != 0) return 0;
	struct winsize ws;
	memset(&ws, 0xA5, sizeof ws);
	if (ioctl(1, TIOCGWINSZ, &ws) != 0 || ws.ws_row != 0 || ws.ws_col != 0) return 0;
	int waiting = -1;
	if (ioctl(0, FIONREAD, &waiting) != 0 || waiting != 0) return 0;
	errno = 0;
	if (syscall(SYS_rt_sigprocmask, SIG_BLOCK, &block, (void *)16, 8) != -1 || errno != EFAULT) return 0;
	return 1;
}

/* The callee-saved registers a guest function finds on entry: all zero, not
 * the host's (2026-10-18). Read before anything of the function can touch
 * them. */
ECL_EXPORT __attribute__((naked)) uint64_t CalleeSavedOnEntry(void) {
#if defined(__aarch64__)
	/* x19-x28 and the frame pointer (d8-d15 are EntryXmm's) */
	__asm__ volatile(
		"orr x0, x19, x20\n\t"
		"orr x0, x0, x21\n\t"
		"orr x0, x0, x22\n\t"
		"orr x0, x0, x23\n\t"
		"orr x0, x0, x24\n\t"
		"orr x0, x0, x25\n\t"
		"orr x0, x0, x26\n\t"
		"orr x0, x0, x27\n\t"
		"orr x0, x0, x28\n\t"
		"orr x0, x0, x29\n\t"
		"ret");
#elif defined(__x86_64__)
	__asm__ volatile(
		"movq %rbx, %rax\n\t"
		"orq %rbp, %rax\n\t"
		"orq %r12, %rax\n\t"
		"orq %r13, %rax\n\t"
		"orq %r14, %rax\n\t"
		"orq %r15, %rax\n\t"
		"ret");
#else
#error "miniBox runs on x86-64 and aarch64 only"
#endif
}

/* A length that is not a whole number of pages is rounded up, as the kernel
 * does: mmap always did, and mprotect, munmap and madvise refused it
 * (2026-10-18). */
ECL_EXPORT int UnalignedLengthsRoundUp(void) {
	uint8_t *p = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) return 0;
	p[4096] = 1;
	if (mprotect(p, 4097, PROT_READ) != 0) return 0;
	if (madvise(p, 10, MADV_DONTNEED) != 0) return 0;
	if (munmap(p, 4097) != 0) return 0;         /* two pages */
	if (munmap(p + 8192, 1) != 0) return 0;     /* and the third */
	return 1;
}

#if defined(__x86_64__)   /* aarch64 has no direction flag */
/* Returns with the direction flag set, which no correct function does: the
 * host must not run on with it (2026-10-18). */
ECL_EXPORT __attribute__((naked)) int ReturnsBackwards(void) {
	__asm__ volatile("std\n\tmovl $1, %eax\n\tret");
}
#endif

/* A cancellable call keeps its fourth argument. With pthread_cancel linked,
 * musl makes such calls through __syscall_cp_asm, which put the fourth in r10,
 * where a call into the host does not look, so pread's offset was lost
 * (2026-10-18). */
static volatile int g_never;
ECL_EXPORT int CancellableCallKeepsItsArguments(void) {
	if (g_never) pthread_cancel(pthread_self());   /* brings in the cancellable path */
	int fd = open("seed", O_RDONLY);
	if (fd < 0) return 0;
	uint8_t all[4], two[2];
	if (read(fd, all, 4) != 4) return 0;
	if (pread(fd, two, 2, 1) != 2) return 0;
	close(fd);
	return two[0] == all[1] && two[1] == all[2];
}

/* The floating-point control words are the guest's own (mb_context,
 * 2026-10-18): what it sees on entry, and that what it sets survives an
 * exported call, a syscall and a host callback. Read as (fcw << 32) | mxcsr;
 * on aarch64 FPCR in the MXCSR place and 0 for the x87 word. */
static uint64_t fpu_read(void) {
#if defined(__aarch64__)
	uint64_t v;
	__asm__ volatile("mrs %0, fpcr" : "=r"(v));
	return (uint32_t)v;
#elif defined(__x86_64__)
	uint16_t cw; uint32_t mx;
	__asm__ volatile("fnstcw %0\n\tstmxcsr %1" : "=m"(cw), "=m"(mx));
	return ((uint64_t)cw << 32) | mx;
#else
#error "miniBox runs on x86-64 and aarch64 only"
#endif
}
ECL_EXPORT uint64_t FpuSeen(void) { return fpu_read(); }
/* what the guest's start-up code (its constructors) ran with */
static uint64_t g_fpu_at_start;
__attribute__((constructor)) static void fpu_at_start(void) { g_fpu_at_start = fpu_read(); }
ECL_EXPORT uint64_t FpuAtStart(void) { return g_fpu_at_start; }
ECL_EXPORT void FpuSet(uint32_t fcw, uint32_t mxcsr) {
#if defined(__aarch64__)
	(void)fcw;
	__asm__ volatile("msr fpcr, %0" : : "r"((uint64_t)mxcsr));
#elif defined(__x86_64__)
	const uint16_t cw = (uint16_t)fcw;
	__asm__ volatile("fldcw %0\n\tldmxcsr %1" : : "m"(cw), "m"(mxcsr));
#else
#error "miniBox runs on x86-64 and aarch64 only"
#endif
}
ECL_EXPORT uint64_t FpuAfterSyscall(void) { (void)getpid(); return fpu_read(); }
ECL_EXPORT uint64_t FpuAfterCallback(void) { if (g_log_cb) g_log_cb(0); return fpu_read(); }

/* A page nothing writes before a state is taken: clean after a load, so the
 * first write to it after one faults and is tracked. */
static volatile uint32_t g_clean_page[1024] __attribute__((aligned(4096)));
ECL_EXPORT uint32_t WriteCleanPage(void) { return ++g_clean_page[0]; }

/* System calls handed a pointer into memory the guest gave back: each answers
 * EFAULT, as on Linux, and the machine lives on. Before 2026-10-18 the host
 * followed most of them and the process died. 0 when right; a bit per call. */
ECL_EXPORT uint32_t BadPointersRefused(void) {
	uint8_t *gone = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (gone == MAP_FAILED) return 0x80000000u;
	munmap(gone, 8192);
	const int fd = open("seed", O_RDONLY);
	if (fd < 0) return 0x40000000u;
	uint32_t bad = 0;
	struct iovec iov = { gone, 4 };
	errno = 0; if (syscall(SYS_read, fd, gone, 4) != -1 || errno != EFAULT) bad |= 1u << 0;
	errno = 0; if (syscall(SYS_write, 1, gone, 4) != -1 || errno != EFAULT) bad |= 1u << 1;
	errno = 0; if (syscall(SYS_clock_gettime, 1, gone) != -1 || errno != EFAULT) bad |= 1u << 2;
	errno = 0; if (syscall(SYS_getrandom, gone, 8, 0) != -1 || errno != EFAULT) bad |= 1u << 3;
	errno = 0; if (syscall(SYS_futex, gone, 128 /* FUTEX_WAIT_PRIVATE */, 0, 0, 0, 0) != -1 || errno != EFAULT) bad |= 1u << 4;
	errno = 0; if (syscall(SYS_fstat, fd, gone) != -1 || errno != EFAULT) bad |= 1u << 5;
	errno = 0; if (syscall(SYS_readv, fd, &iov, 1) != -1 || errno != EFAULT) bad |= 1u << 6;
	errno = 0; if (syscall(SYS_readv, fd, gone, 1) != -1 || errno != EFAULT) bad |= 1u << 7;
	errno = 0; if (syscall(SYS_sysinfo, gone) != -1 || errno != EFAULT) bad |= 1u << 8;
	errno = 0; if (syscall(SYS_sched_getaffinity, 0, 8, gone) != -1 || errno != EFAULT) bad |= 1u << 9;
	errno = 0; if (syscall(SYS_pread64, fd, gone, 4, 0) != -1 || errno != EFAULT) bad |= 1u << 10;
	errno = 0; if (syscall(SYS_truncate, gone, 0) != -1 || errno != EFAULT) bad |= 1u << 11;
	close(fd);
	return bad;
}

/* Calls that go nowhere: through a null pointer, to an address nothing is
 * mapped at, and to a callback slot the host never registered (slot 63). Each
 * is the guest's death, not the host's (2026-10-18). */
ECL_EXPORT void CallNull(void) { void (*volatile f)(void) = 0; f(); }
ECL_EXPORT void CallWild(void) { void (*volatile f)(void) = (void (*)(void))(uintptr_t)0x123456789ull; f(); }
ECL_EXPORT void CallUnregisteredSlot(void) { void (*volatile f)(void) = (void (*)(void))(uintptr_t)(0x35f00000300ull + 63 * 16); f(); }

/* Open files and the entropy stream are part of a state (2026-10-18): a disc
 * read through a descriptor, which a disc swap closes and opens again */
static int g_disc = -1;
ECL_EXPORT int DiscOpen(int which) { g_disc = open(which ? "disc2" : "disc1", O_RDONLY); return g_disc; }
ECL_EXPORT int DiscClose(void) { const int r = close(g_disc); g_disc = -1; return r; }
ECL_EXPORT uint32_t DiscRead4(void) { uint32_t v = 0; return read(g_disc, &v, 4) == 4 ? v : 0xFFFFFFFFu; }
ECL_EXPORT uint64_t Entropy(void) { uint64_t v = 0; return getrandom(&v, sizeof v, 0) == (ssize_t)sizeof v ? v : 0; }

/* sysinfo, as the kit this guest was built with is answered: 1 for the
 * answer with mem_unit where it belongs (kit revision 1 or later), 0 for the
 * old one (unit written into freehigh's top half), -1 for neither */
ECL_EXPORT int SysinfoAnswer(void) {
	struct sysinfo si;
	memset(&si, 0xA5, sizeof si);
	if (sysinfo(&si) != 0) return -1;
	if (si.totalram != (1024ul << 20) || si.freeram != (512ul << 20)) return -1;
	if (si.mem_unit == 1 && si.freehigh == 0) return 1;
	if (si.mem_unit == 0 && si.freehigh == (1ul << 32)) return 0;
	return -1;
}

/* The file answers, as the kit this guest was built with is answered: 2 for
 * Linux's (kit revision 2: EBADF for a descriptor that is not open, ESPIPE
 * for seeking a stream, a seek past the end allowed and end of file there),
 * 0 for the old ones, anything else for a mix. */
ECL_EXPORT int FileAnswers(void) {
	int now = 0, old = 0;
	char b[8];
	struct stat st;
	errno = 0; long r = syscall(SYS_read, 99, b, 1);
	if (r == -1 && errno == EBADF) now |= 1; else if (r == -1 && errno == ENOENT) old |= 1;
	errno = 0; r = syscall(SYS_lseek, 99, 0, SEEK_SET);
	if (r == -1 && errno == EBADF) now |= 2; else if (r == -1 && errno == EINVAL) old |= 2;
	errno = 0; r = syscall(SYS_lseek, 1, 0, SEEK_SET);
	if (r == -1 && errno == ESPIPE) now |= 4; else if (r == -1 && errno == EINVAL) old |= 4;
	errno = 0; r = syscall(SYS_fstat, 99, &st);
	if (r == -1 && errno == EBADF) now |= 8; else if (r == -1 && errno == ENOENT) old |= 8;
	const int fd = open("seed", O_RDONLY);
	if (fd < 0) return -1;
	errno = 0; r = syscall(SYS_lseek, fd, 100, SEEK_SET);
	if (r == 100) { now |= 16; if (syscall(SYS_read, fd, b, 4) == 0) now |= 32; }
	else if (r == -1 && errno == EINVAL) old |= 16 | 32;
	errno = 0; r = syscall(SYS_pread64, fd, b, 4, 100);
	if (r == 0) now |= 64; else if (r == -1 && errno == EINVAL) old |= 64;
	close(fd);
	if (now == 127) return 2;
	if (old == 127) return 0;
	return -1 - now * 256 - old;
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

/* Two guests that never come back from a call, for the stop the host asks
 * for from another thread (wbx_stop_guest, 2026-10-19): one loops in its own
 * code and makes no system call, one loops on system calls. And n calls of
 * each kind for the host's count of working calls (wbx_guest_activity): a
 * yield is not work, a getppid is. */
static volatile uint64_t g_spun;
ECL_EXPORT int SpinForever(void) { for (;;) g_spun++; }
ECL_EXPORT int SpinOnSyscalls(void) { for (;;) syscall(SYS_sched_yield); }
ECL_EXPORT void Yield(int n) { for (int i = 0; i < n; i++) syscall(SYS_sched_yield); }
ECL_EXPORT void Work(int n) { for (int i = 0; i < n; i++) syscall(SYS_getppid); }
/* calls the host (the log callback), then yields n times: a stop asked for
 * inside the callback ends it at the first yield, unless it was dropped */
ECL_EXPORT int CallHostThenYield(int n) {
	g_log_cb(7);
	for (int i = 0; i < n; i++) syscall(SYS_sched_yield);
	return 1;
}

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

/* The same three boundaries for the vector registers: what the guest finds in
 * xmm0-15 on entering an export, after a syscall, and after a host callback.
 * Each reads the sixteen registers OR'ed together (0: all clear). The syscall
 * and callback cases fill every register with ones first, so a host that
 * leaves them alone fails as surely as one that leaves its own values there;
 * the entry case relies on run_guest filling xmm0-5 before the call. The host
 * used to leave its own values in them - a guest's varargs prologue spills
 * xmm0-7, and a JVM in the box carried host heap addresses into its states
 * that way (interop_bin.c). */
#if defined(__aarch64__)
/* aarch64: v0-v31, and AAPCS64 makes a callee keep d8-d15 (the low halves of
 * v8-v15), so after a syscall and after a callback those halves are the
 * guest's own ones and only the upper halves of v8-v15 are read; on entry all
 * thirty-two are (run_guest fills every one before the call). The syscall and
 * callback probes keep d8-d15 for their own caller. */
#define WBX_FILL_V \
	"\tmovi v0.2d, #0xffffffffffffffff\n\tmovi v1.2d, #0xffffffffffffffff\n\tmovi v2.2d, #0xffffffffffffffff\n\tmovi v3.2d, #0xffffffffffffffff\n" \
	"\tmovi v4.2d, #0xffffffffffffffff\n\tmovi v5.2d, #0xffffffffffffffff\n\tmovi v6.2d, #0xffffffffffffffff\n\tmovi v7.2d, #0xffffffffffffffff\n" \
	"\tmovi v8.2d, #0xffffffffffffffff\n\tmovi v9.2d, #0xffffffffffffffff\n\tmovi v10.2d, #0xffffffffffffffff\n\tmovi v11.2d, #0xffffffffffffffff\n" \
	"\tmovi v12.2d, #0xffffffffffffffff\n\tmovi v13.2d, #0xffffffffffffffff\n\tmovi v14.2d, #0xffffffffffffffff\n\tmovi v15.2d, #0xffffffffffffffff\n" \
	"\tmovi v16.2d, #0xffffffffffffffff\n\tmovi v17.2d, #0xffffffffffffffff\n\tmovi v18.2d, #0xffffffffffffffff\n\tmovi v19.2d, #0xffffffffffffffff\n" \
	"\tmovi v20.2d, #0xffffffffffffffff\n\tmovi v21.2d, #0xffffffffffffffff\n\tmovi v22.2d, #0xffffffffffffffff\n\tmovi v23.2d, #0xffffffffffffffff\n" \
	"\tmovi v24.2d, #0xffffffffffffffff\n\tmovi v25.2d, #0xffffffffffffffff\n\tmovi v26.2d, #0xffffffffffffffff\n\tmovi v27.2d, #0xffffffffffffffff\n" \
	"\tmovi v28.2d, #0xffffffffffffffff\n\tmovi v29.2d, #0xffffffffffffffff\n\tmovi v30.2d, #0xffffffffffffffff\n\tmovi v31.2d, #0xffffffffffffffff\n"
/* v0-v7 and v16-v31 OR'ed into v0, then both its halves into x0 */
#define WBX_OR_V_SCRATCH_INTO_X0 \
	"\torr v0.16b, v0.16b, v1.16b\n\torr v0.16b, v0.16b, v2.16b\n\torr v0.16b, v0.16b, v3.16b\n\torr v0.16b, v0.16b, v4.16b\n" \
	"\torr v0.16b, v0.16b, v5.16b\n\torr v0.16b, v0.16b, v6.16b\n\torr v0.16b, v0.16b, v7.16b\n\torr v0.16b, v0.16b, v16.16b\n" \
	"\torr v0.16b, v0.16b, v17.16b\n\torr v0.16b, v0.16b, v18.16b\n\torr v0.16b, v0.16b, v19.16b\n\torr v0.16b, v0.16b, v20.16b\n" \
	"\torr v0.16b, v0.16b, v21.16b\n\torr v0.16b, v0.16b, v22.16b\n\torr v0.16b, v0.16b, v23.16b\n\torr v0.16b, v0.16b, v24.16b\n" \
	"\torr v0.16b, v0.16b, v25.16b\n\torr v0.16b, v0.16b, v26.16b\n\torr v0.16b, v0.16b, v27.16b\n\torr v0.16b, v0.16b, v28.16b\n" \
	"\torr v0.16b, v0.16b, v29.16b\n\torr v0.16b, v0.16b, v30.16b\n\torr v0.16b, v0.16b, v31.16b\n" \
	"\tmov x0, v0.d[0]\n\tmov x1, v0.d[1]\n\torr x0, x0, x1\n"
/* ...and the upper halves of v8-v15 */
#define WBX_OR_V8_15_HIGH_INTO_X0 \
	"\tmov x1, v8.d[1]\n\torr x0, x0, x1\n\tmov x1, v9.d[1]\n\torr x0, x0, x1\n" \
	"\tmov x1, v10.d[1]\n\torr x0, x0, x1\n\tmov x1, v11.d[1]\n\torr x0, x0, x1\n" \
	"\tmov x1, v12.d[1]\n\torr x0, x0, x1\n\tmov x1, v13.d[1]\n\torr x0, x0, x1\n" \
	"\tmov x1, v14.d[1]\n\torr x0, x0, x1\n\tmov x1, v15.d[1]\n\torr x0, x0, x1\n"
/* ...and the low halves of v8-v15 too: on entry */
#define WBX_OR_V8_15_LOW_INTO_X0 \
	"\tfmov x1, d8\n\torr x0, x0, x1\n\tfmov x1, d9\n\torr x0, x0, x1\n" \
	"\tfmov x1, d10\n\torr x0, x0, x1\n\tfmov x1, d11\n\torr x0, x0, x1\n" \
	"\tfmov x1, d12\n\torr x0, x0, x1\n\tfmov x1, d13\n\torr x0, x0, x1\n" \
	"\tfmov x1, d14\n\torr x0, x0, x1\n\tfmov x1, d15\n\torr x0, x0, x1\n"
#define WBX_SAVE_D8_15 \
	"\tstp x29, x30, [sp, #-80]!\n" \
	"\tstp d8, d9, [sp, #16]\n\tstp d10, d11, [sp, #32]\n\tstp d12, d13, [sp, #48]\n\tstp d14, d15, [sp, #64]\n"
#define WBX_RESTORE_D8_15 \
	"\tldp d8, d9, [sp, #16]\n\tldp d10, d11, [sp, #32]\n\tldp d12, d13, [sp, #48]\n\tldp d14, d15, [sp, #64]\n" \
	"\tldp x29, x30, [sp], #80\n"
__asm__(
	".text\n"
	".globl EntryXmm\n.type EntryXmm,%function\n"
	"EntryXmm:\n"
	WBX_OR_V_SCRATCH_INTO_X0
	WBX_OR_V8_15_HIGH_INTO_X0
	WBX_OR_V8_15_LOW_INTO_X0
	"\tret\n"
	".globl SyscallXmm\n.type SyscallXmm,%function\n"
	"SyscallXmm:\n"
	WBX_SAVE_D8_15
	WBX_FILL_V
	"\tmov x0, #0\n"
	"\tmov x8, #12\n"
	"\tmovz x16, #0x0080\n"
	"\tmovk x16, #0x035f, lsl #32\n"
	"\tblr x16\n"
	WBX_OR_V_SCRATCH_INTO_X0
	WBX_OR_V8_15_HIGH_INTO_X0
	WBX_RESTORE_D8_15
	"\tret\n"
	".globl ExtcallXmm\n.type ExtcallXmm,%function\n"
	"ExtcallXmm:\n"
	WBX_SAVE_D8_15
	"\tadrp x1, g_log_cb\n"
	"\tldr x1, [x1, #:lo12:g_log_cb]\n"
	"\tcbz x1, 1f\n"
	WBX_FILL_V
	"\tmov x0, #0\n"
	"\tblr x1\n"
	WBX_OR_V_SCRATCH_INTO_X0
	WBX_OR_V8_15_HIGH_INTO_X0
	WBX_RESTORE_D8_15
	"\tret\n"
	"1:\n"
	"\tmov x0, #1\n"
	WBX_RESTORE_D8_15
	"\tret\n");
#elif defined(__x86_64__)
#define FILL_XMM \
	"\tpcmpeqd %xmm0, %xmm0\n\tpcmpeqd %xmm1, %xmm1\n\tpcmpeqd %xmm2, %xmm2\n\tpcmpeqd %xmm3, %xmm3\n" \
	"\tpcmpeqd %xmm4, %xmm4\n\tpcmpeqd %xmm5, %xmm5\n\tpcmpeqd %xmm6, %xmm6\n\tpcmpeqd %xmm7, %xmm7\n" \
	"\tpcmpeqd %xmm8, %xmm8\n\tpcmpeqd %xmm9, %xmm9\n\tpcmpeqd %xmm10, %xmm10\n\tpcmpeqd %xmm11, %xmm11\n" \
	"\tpcmpeqd %xmm12, %xmm12\n\tpcmpeqd %xmm13, %xmm13\n\tpcmpeqd %xmm14, %xmm14\n\tpcmpeqd %xmm15, %xmm15\n"
#define OR_XMM_INTO_RAX \
	"\tpor %xmm1, %xmm0\n\tpor %xmm2, %xmm0\n\tpor %xmm3, %xmm0\n\tpor %xmm4, %xmm0\n" \
	"\tpor %xmm5, %xmm0\n\tpor %xmm6, %xmm0\n\tpor %xmm7, %xmm0\n\tpor %xmm8, %xmm0\n" \
	"\tpor %xmm9, %xmm0\n\tpor %xmm10, %xmm0\n\tpor %xmm11, %xmm0\n\tpor %xmm12, %xmm0\n" \
	"\tpor %xmm13, %xmm0\n\tpor %xmm14, %xmm0\n\tpor %xmm15, %xmm0\n" \
	"\tmovq %xmm0, %rax\n\tpsrldq $8, %xmm0\n\tmovq %xmm0, %rdx\n\tor %rdx, %rax\n"
__asm__(
	".text\n"
	".globl EntryXmm\n.type EntryXmm,@function\n"
	"EntryXmm:\n"
	OR_XMM_INTO_RAX
	"\tret\n"
	".globl SyscallXmm\n.type SyscallXmm,@function\n"
	"SyscallXmm:\n"
	"\tpush %rbx\n"
	FILL_XMM
	"\txor %edi, %edi\n"
	"\tmov $12, %eax\n"
	"\tmovabs $0x35f00000080, %r10\n"
	"\tcall *%r10\n"
	OR_XMM_INTO_RAX
	"\tpop %rbx\n"
	"\tret\n"
	".globl ExtcallXmm\n.type ExtcallXmm,@function\n"
	"ExtcallXmm:\n"
	"\tpush %rbx\n"
	"\tmov g_log_cb(%rip), %rax\n"
	"\ttest %rax, %rax\n"
	"\tjz 1f\n"
	FILL_XMM
	"\txor %edi, %edi\n"
	"\tcall *%rax\n"
	OR_XMM_INTO_RAX
	"\tpop %rbx\n"
	"\tret\n"
	"1:\n"
	"\tmov $1, %eax\n"
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
