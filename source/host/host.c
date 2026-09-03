/* WaterboxHost: ties the memory block, ELF loader, VFS, and context together;
 * dispatches guest syscalls; seals; saves/loads top-level state. Faithful C
 * port of BizHawk waterboxhost src/host.rs (Linux single-thread subset). */
#define _GNU_SOURCE
#include "minibox_internal.h"
#include "minibox_threads.h"
#include "minibox.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct mb_host {
	mb_fs *fs;
	uintptr_t program_break;
	mb_elf *elf;
	mb_layout layout;
	mb_block *block;
	bool active, sealed;
	uint8_t *image; size_t image_len;
	mb_context context;
	mb_thunks *thunks;
	mb_threads *threads;
	uint64_t getrandom_state; /* deterministic entropy stream, per host */
};

/* ---- syscall numbers (x86-64) ---- */
enum {
	NR_read=0, NR_write=1, NR_open=2, NR_close=3, NR_stat=4, NR_fstat=5, NR_lseek=8,
	NR_mmap=9, NR_mprotect=10, NR_munmap=11, NR_brk=12, NR_rt_sigprocmask=14,
	NR_ioctl=16, NR_readv=19, NR_writev=20, NR_sched_yield=24, NR_mremap=25, NR_madvise=28,
	NR_nanosleep=35, NR_getpid=39, NR_exit=60, NR_truncate=76, NR_ftruncate=77,
	NR_getppid=110, NR_gettid=186, NR_futex=202, NR_sched_getaffinity=204, NR_pread64=17, NR_sysinfo=99, NR_prctl=157, NR_openat=257, NR_newfstatat=262, NR_set_thread_area=205, NR_clock_nanosleep=230,
	NR_clock_gettime=228, NR_set_tid_address=218, NR_getrandom=318, NR_fcntl=72, NR_wbx_clone=2000
};

#define MAP_ANONYMOUS 0x20
#define MAP_STACK 0x20000
#define MAP_FIXED_NOREPLACE 0x100000
#define MADV_DONTNEED 4
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_REQUEUE 3
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7

static uintptr_t serr(int e) { return (uintptr_t)(intptr_t)(-e); }  /* -errno as usize */
static uintptr_t sok(mb_sword v) { return (uintptr_t)v; }

static mb_prot arg_to_prot(uintptr_t a, bool *bad) {
	*bad = false;
	if (a & ~(uintptr_t)(PROT_READ|PROT_WRITE|PROT_EXEC)) { *bad = true; return MB_PROT_NONE; }
	if (a & PROT_EXEC) return (a & PROT_WRITE) ? MB_PROT_RWX : MB_PROT_RX;
	if (a & PROT_WRITE) return MB_PROT_RW;
	if (a & PROT_READ) return MB_PROT_R;
	return MB_PROT_NONE;
}

/* The guest syscall dispatcher (sysv64; installed in the Context). */
/* Called BY the interop blob, so it is sysv64 even on a Windows host. */
/* Set MINIBOX_TRACE_SYSCALLS=1 to log every guest syscall as it happens. The
 * guest is a sandbox: when it dies there is no core dump to read and no debugger
 * attached, so the last logged syscall is usually the whole diagnosis. Flushed
 * per line, because whatever kills the process will not flush for us. */
static int trace_syscalls(void) {
	static int on = -1;
	if (on < 0) { const char *e = getenv("MINIBOX_TRACE_SYSCALLS"); on = e && *e && *e != '0'; }
	return on;
}

static uintptr_t MB_SYSV dispatch_inner(uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
                          uintptr_t a5, uintptr_t a6, uintptr_t nr, void *hp);

/* Tracing wrapper: the arguments go out BEFORE the syscall runs (a crash
 * inside it still shows what was asked), the result right after - a call
 * that fails where it succeeds elsewhere is exactly what a trace diff is
 * for, and the result column is where that shows. */
static uintptr_t MB_SYSV dispatch(uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
                          uintptr_t a5, uintptr_t a6, uintptr_t nr, void *hp) {
#ifdef MB_HAVE_FSBASE
	/* The guest trapped in here with %fs = its own thread pointer (a Rust guest
	 * uses %fs-direct TLS), but everything below is host C and glibc - malloc
	 * and fprintf read the host's TLS through %fs. Put the host's back for the
	 * body, and the guest's back before returning to guest code. thread_area is
	 * 0 only during early _start, when the guest is still on %gs and keeping
	 * host %fs is the right answer. */
	mb_host *hfs = (mb_host *)hp;
	const bool swap_fs = hfs->context.fs_swap; /* plain load: NO call may precede the swap */
	if (swap_fs) mb_wrfsbase(hfs->context.host_fs);
#endif
	uintptr_t res;
	if (!trace_syscalls()) {
		res = dispatch_inner(a1, a2, a3, a4, a5, a6, nr, hp);
	} else {
		fprintf(stderr, "[syscall] %llu (%llx, %llx, %llx)", (unsigned long long)nr,
		        (unsigned long long)a1, (unsigned long long)a2, (unsigned long long)a3);
		fflush(stderr);
		res = dispatch_inner(a1, a2, a3, a4, a5, a6, nr, hp);
		intptr_t s = (intptr_t)res;
		if (s < 0 && s > -4096) fprintf(stderr, " -> ERR %lld\n", (long long)s);
		else fprintf(stderr, " -> %llx\n", (unsigned long long)res);
		fflush(stderr);
	}
#ifdef MB_HAVE_FSBASE
	if (swap_fs) {
		mb_wrfsbase(hfs->context.thread_area ? hfs->context.thread_area
		                                     : hfs->context.host_fs);
	}
#endif
	return res;
}

static uintptr_t MB_SYSV dispatch_inner(uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
                          uintptr_t a5, uintptr_t a6, uintptr_t nr, void *hp) {
	mb_host *h = (mb_host *)hp;
	(void)a6;
	switch (nr) {
		case NR_mmap: {
			bool bad; mb_prot prot = arg_to_prot(a3, &bad); if (bad) return serr(EINVAL);
			uintptr_t flags = a4;
			if (!(flags & MAP_ANONYMOUS)) return serr(EOPNOTSUPP);
			if (flags & 0xf00) return serr(EOPNOTSUPP);
			if (flags & MAP_STACK) { if (prot == MB_PROT_RW) prot = MB_PROT_RWSTACK; else return serr(EINVAL); }
			bool no_replace = (flags & MAP_FIXED_NOREPLACE) != 0;
			/* the kernel rounds an unaligned length up to a page; so do we */
			mb_range r = { a1, (a2 + 0xFFF) & ~(uintptr_t)0xFFF };
			mb_sword res = mb_block_mmap(h->block, r, prot, h->layout.mmap_arena, no_replace);
			return res < 0 ? serr((int)-res) : sok(res);
		}
		case NR_mremap: {
			mb_range r = { a1, a2 };
			mb_sword res = mb_block_mremap(h->block, r, a3, h->layout.mmap_arena);
			return res < 0 ? serr((int)-res) : sok(res);
		}
		case NR_mprotect: {
			bool bad; mb_prot prot = arg_to_prot(a3, &bad); if (bad) return serr(EINVAL);
			mb_range r = { a1, a2 };
			int res = mb_block_mprotect(h->block, r, prot);
			return res ? serr(-res) : sok(0);
		}
		case NR_munmap: { mb_range r = { a1, a2 }; int res = mb_block_munmap(h->block, r); return res ? serr(-res) : sok(0); }
		case NR_madvise:
			if (a3 == MADV_DONTNEED) { mb_range r = { a1, a2 }; int res = mb_block_madvise_dontneed(h->block, r); return res ? serr(-res) : sok(0); }
			return sok(0);
		case NR_brk: {
			mb_range arena = h->layout.sbrk; uintptr_t old = h->program_break, res;
			if (a1 != mb_align_down(a1)) res = old;
			else if (a1 < arena.start) res = old;
			else if (a1 > mb_range_end(arena)) { fprintf(stderr, "miniBox: sbrk heap exhausted\n"); res = old; }
			else if (a1 > old) { mb_range r = { old, a1 - old }; mb_block_mmap_fixed(h->block, r, MB_PROT_RW, true); res = a1; }
			else res = old;
			h->program_break = res; return sok((mb_sword)res);
		}
		case NR_stat:  { mb_sword r = mb_fs_stat_name(h->fs, (const char *)a1, (void *)a2); return r < 0 ? serr((int)-r) : sok(0); }
		case NR_fstat: { mb_sword r = mb_fs_stat_fd(h->fs, (int)a1, (void *)a2); return r < 0 ? serr((int)-r) : sok(0); }
		case NR_ioctl: return sok(0);
		case NR_read:  { mb_sword r = mb_fs_read(h->fs, (int)a1, (uint8_t *)a2, a3); return r < 0 ? serr((int)-r) : sok(r); }
		case NR_write: { mb_sword r = mb_fs_write(h->fs, (int)a1, (const uint8_t *)a2, a3); return r < 0 ? serr((int)-r) : sok(r); }
		case NR_readv: case NR_writev: {
			/* iovec: {void* base; size_t len} */
			struct iov { uintptr_t base; uintptr_t len; } *iov = (struct iov *)a2;
			mb_sword total = 0;
			for (uintptr_t i = 0; i < a3; i++) {
				if (!iov[i].base) continue;
				mb_sword r = (nr == NR_readv)
					? mb_fs_read(h->fs, (int)a1, (uint8_t *)iov[i].base, iov[i].len)
					: mb_fs_write(h->fs, (int)a1, (const uint8_t *)iov[i].base, iov[i].len);
				if (r < 0) return serr((int)-r);
				total += r;
			}
			return sok(total);
		}
		case NR_open:  { mb_sword r = mb_fs_open(h->fs, (const char *)a1, (int)a2); return r < 0 ? serr((int)-r) : sok(r); }
		case NR_sysinfo: {
			/* fixed, plausible, deterministic: 1GB total, half free, no swap.
			 * (struct sysinfo is 112 bytes of longs; fill what matters.) */
			uint64_t *si = (uint64_t *)a1;
			memset(si, 0, 112);
			si[0] = 0;                    /* uptime */
			si[4] = 1024ull << 20;        /* totalram */
			si[5] = 512ull << 20;         /* freeram */
			((uint32_t *)a1)[100 / 4] = 1; /* mem_unit at offset 100 */
			return sok(0);
		}
		case NR_prctl:
			/* PR_SET_NAME: a label, not a behavior - accepted and ignored */
			return (int)a1 == 15 ? sok(0) : serr(EINVAL);
		case NR_pread64: {
			/* read at an offset, position untouched. Guest threads cannot
			 * interleave inside one host syscall, so save/seek/read/restore
			 * is atomic as far as any guest can observe. */
			mb_sword pos = mb_fs_seek(h->fs, (int)a1, 0, 1 /* SEEK_CUR */);
			if (pos < 0) return serr((int)-pos);
			mb_sword r = mb_fs_seek(h->fs, (int)a1, (mb_sword)a4, 0 /* SEEK_SET */);
			if (r < 0) return serr((int)-r);
			mb_sword n = mb_fs_read(h->fs, (int)a1, (void *)a2, a3);
			mb_fs_seek(h->fs, (int)a1, pos, 0);
			return n < 0 ? serr((int)-n) : sok(n);
		}
		case NR_openat: {
			/* only the openat that IS open: std::filesystem and newer libcs
			 * reach the flat namespace through AT_FDCWD; a real dirfd has no
			 * meaning here. */
			if ((int)a1 != -100) return serr(EBADF);
			mb_sword r = mb_fs_open(h->fs, (const char *)a2, (int)a3);
			return r < 0 ? serr((int)-r) : sok(r);
		}
		case NR_newfstatat: {
			if ((int)a1 != -100) return serr(EBADF);
			mb_sword r = mb_fs_stat_name(h->fs, (const char *)a2, (void *)a3);
			return r < 0 ? serr((int)-r) : sok(0);
		}
		case NR_close: { mb_sword r = mb_fs_close(h->fs, (int)a1); return r < 0 ? serr((int)-r) : sok(0); }
		case NR_lseek: { mb_sword r = mb_fs_seek(h->fs, (int)a1, (mb_sword)a2, (int)a3); return r < 0 ? serr((int)-r) : sok(r); }
		case NR_truncate:  { mb_sword r = mb_fs_truncate_name(h->fs, (const char *)a1, (mb_sword)a2); return r < 0 ? serr((int)-r) : sok(0); }
		case NR_ftruncate: { mb_sword r = mb_fs_truncate_fd(h->fs, (int)a1, (mb_sword)a2); return r < 0 ? serr((int)-r) : sok(0); }
		case NR_clock_gettime: {
			int64_t *ts = (int64_t *)a2;  /* {tv_sec, tv_nsec} */
			ts[0] = 1495889068; ts[1] = 0; return sok(0);
		}
		case NR_getrandom: {
			/* Determinism is the whole contract, so randomness cannot be real:
			 * fill the buffer from a fixed-seed splitmix64. std seeds every
			 * HashMap's RandomState through this call, so a guest that uses a
			 * hash map (every Rust guest does) needs it, and needs it the same
			 * every run. The stream is per-host and resets with the host, like
			 * clock_gettime's constant time; it is not part of the machine
			 * state because a seed drawn once at startup never re-reads. */
			uint8_t *buf = (uint8_t *)a1;
			uint64_t n = a2;
			for (uint64_t i = 0; i < n; i += 8) {
				h->getrandom_state += 0x9E3779B97F4A7C15ull;
				uint64_t z = h->getrandom_state;
				z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
				z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
				z = z ^ (z >> 31);
				uint64_t take = n - i < 8 ? n - i : 8;
				memcpy(buf + i, &z, take);
			}
			return sok((mb_sword)n);
		}
		case NR_fcntl: {
			/* Only the descriptor-flag commands, and only nominally: there is no
			 * exec in a sandbox, so close-on-exec means nothing, and the VFS has
			 * no non-blocking mode to set. Rust's File::open sets FD_CLOEXEC on
			 * every handle it opens, which is how this first came up. */
			switch ((int)a2) {
				case 1: /* F_GETFD */ case 3: /* F_GETFL */ return sok(0);
				case 2: /* F_SETFD */ case 4: /* F_SETFL */ return sok(0);
				default: return serr(EINVAL);
			}
		}
		case NR_rt_sigprocmask: return sok(0);
		case NR_set_thread_area: return serr(ENOSYS);   /* musl handles in userspace */
		case NR_set_tid_address: return sok(mb_threads_set_tid_address(h->threads, a1));
		case NR_gettid: return sok(mb_threads_get_tid(h->threads));
		case NR_getpid: case NR_getppid: return sok(1);
		case NR_sched_yield: case NR_nanosleep: case NR_clock_nanosleep:
			return mb_threads_yield(h->threads, &h->context);
		case NR_wbx_clone: {
			/* args: (tls/thread_area, child_rsp, child_rip, child_tid, parent_tid*) */
			mb_sword r = mb_threads_spawn(h->threads, h->block, a1, a2, a3, a4, (uint32_t *)a5);
			return r < 0 ? serr((int)-r) : sok(r);
		}
		case NR_sched_getaffinity: {
			/* one CPU, honestly: pools and hardware_concurrency stay deterministic.
			 * musl's sysconf(_SC_NPROCESSORS_*) issues this syscall directly, so a
			 * libc-level shadow cannot answer it. Returns the kernel's cpumask
			 * size in bytes, like Linux. */
			if (a3 == 0 || a2 < 8) return serr(EINVAL);
			memset((void *)a3, 0, a2);
			*(uint8_t *)a3 = 1;
			return sok(8);
		}
		case NR_exit: return mb_threads_exit(h->threads, &h->context);
		case NR_futex: {
			int op = (int)a2 & ~FUTEX_PRIVATE_FLAG;
			switch (op) {
				case FUTEX_WAIT: return mb_threads_futex_wait(h->threads, &h->context, a1, (uint32_t)a3);
				case FUTEX_WAKE: return sok(mb_threads_futex_wake(h->threads, a1, (uint32_t)a3));
				case FUTEX_REQUEUE: return sok(mb_threads_futex_requeue(h->threads, a1, a5, (uint32_t)a3, (uint32_t)a4));
				case FUTEX_LOCK_PI: return mb_threads_futex_lock_pi(h->threads, &h->context, a1);
				case FUTEX_UNLOCK_PI: return mb_threads_futex_unlock_pi(h->threads, &h->context, a1);
				default: return serr(ENOSYS);
			}
		}
		default:
			/* flush before trapping: an illegal instruction takes the process down
			 * without running atexit, and a redirected stderr would lose the one
			 * line that explains the crash */
			mb_diag_banner("unimplemented syscall");
			mb_diag("miniBox: unimplemented syscall %llu (%llx, %llx, %llx)\n",
			        (unsigned long long)nr, (unsigned long long)a1,
			        (unsigned long long)a2, (unsigned long long)a3);
			mb_diag("  the guest asked the host for something it does not provide; it cannot continue.\n");
			__builtin_trap();
			return serr(ENOSYS);
	}
}

/* ---- lifecycle ---- */

static void run_proc_if_present(mb_host *h, const char *name) {
	uintptr_t p = mb_elf_proc_addr(h->elf, name);
	if (p) mb_call_guest_simple(p, &h->context);
}

mb_host *mb_host_new(const uint8_t *image, size_t image_len, const char *module_name,
                     const mb_memory_layout_template *tpl, char *errbuf, size_t errlen) {
	mb_host *h = (mb_host *)calloc(1, sizeof(mb_host));
	h->image_len = image_len;
	h->image = (uint8_t *)malloc(image_len);
	memcpy(h->image, image, image_len);
	h->thunks = mb_thunks_new();
	h->threads = mb_threads_new();

	/* build the layout: elf span (page-expanded), then the fixed + sized areas */
	mb_range elf = mb_range_align_expand(mb_elf_span(image, image_len));
	mb_layout *L = &h->layout;
	uintptr_t end = mb_range_end(elf);
	#define ADD(field, sz) do { L->field.start = end; L->field.size = mb_align_up(sz); end = mb_range_end(L->field); } while (0)
	L->elf = elf;
	ADD(main_thread, 1u << 20); ADD(alt_thread, 1u << 20);
	ADD(sbrk, tpl->sbrk_size); ADD(sealed, tpl->sealed_size); ADD(invis, tpl->invis_size);
	ADD(plain, tpl->plain_size); ADD(mmap_arena, tpl->mmap_size);
	#undef ADD
	mb_range all = mb_layout_all(L);
	/* Spec v2: the block may span any number of 4 GiB regions (a PS3 core keeps
	 * a flat 4 GiB guest view plus an 8 GiB dispatch table); only the start
	 * stays 4 GiB aligned. */
	if (all.start & 0xffffffffu) {
		snprintf(errbuf, errlen, "HostMemoryLayout must start on a 4GiB boundary");
		free(h->image); free(h); return NULL;
	}

	h->block = mb_block_new(all);
	if (!h->block) { snprintf(errbuf, errlen, "failed to create memory block"); free(h->image); free(h); return NULL; }
	h->program_break = L->sbrk.start;
	h->fs = mb_fs_new();
	mb_context_init(&h->context, L->main_thread.start + L->main_thread.size,
	                L->alt_thread.start + L->alt_thread.size, dispatch);

	mb_prepare_thread();
	h->context.host_ptr = (uintptr_t)h;
	mb_block_activate(h->block);
	h->active = true;

	if (mb_elf_load(image, image_len, module_name, L, h->block, &h->elf) != 0) {
		snprintf(errbuf, errlen, "failed to load guest ELF");
		mb_block_deactivate(h->block); mb_block_free(h->block); mb_fs_free(h->fs);
		mb_thunks_free(h->thunks); mb_threads_free(h->threads); free(h->image); free(h); return NULL;
	}

	/* Decided before the guest runs a single instruction: a guest carrying
	 * PT_TLS uses %fs-relative thread locals (Rust) and needs the host to hand
	 * it its own %fs; every C/C++ guest on the waterbox musl uses %gs and is
	 * left exactly as it was. */
#ifdef MB_HAVE_FSBASE
	h->context.fs_swap = mb_elf_has_tls(h->elf) && mb_fsbase_ok() && !getenv("MB_NO_FS_SWAP");
#endif

	mb_call_guest_simple(mb_elf_entry(h->elf), &h->context);  /* _start */
	mb_block_deactivate(h->block); h->active = false;
	return h;
}

void mb_host_destroy(mb_host *h) {
	if (!h) return;
	if (h->active) mb_block_deactivate(h->block);
	mb_block_free(h->block); mb_fs_free(h->fs); mb_elf_free(h->elf);
	mb_thunks_free(h->thunks); mb_threads_free(h->threads); free(h->image); free(h);
}

uintptr_t mb_host_proc_addr_raw(mb_host *h, const char *name);

void mb_host_activate(mb_host *h) {
#ifndef _WIN32
	/* guest code will run on THIS thread; make signal delivery on a faulting
	 * tracked stack page possible (see tripguard.c) */
	mb_tripguard_ensure_altstack();
#endif
	/* A guest that exports GuestFaultHandler wants to hear about faults on
	 * pages it protected itself (see tripguard.c) - on BOTH platforms: the
	 * Windows handler is the vectored one, and a guest whose handler is not
	 * registered there dies on its first watched write. The RAW address: it
	 * is called on the faulting guest thread, which is already inside the
	 * guest, so the host-to-guest adapter (a host thread entering) would
	 * find no entry context to save. The guest ABI is spelled in the type. */
	mb_tripguard_set_guest_fault_handler((mb_guest_fault_fn)mb_host_proc_addr_raw(h, "GuestFaultHandler"));
	if (h->active) return;
	mb_prepare_thread();
	h->context.host_ptr = (uintptr_t)h;
	mb_block_activate(h->block);
	h->active = true;
}
void mb_host_deactivate(mb_host *h) {
	if (!h->active) return;
	h->context.host_ptr = 0;
	mb_block_deactivate(h->block);
	h->active = false;
}

uintptr_t mb_host_proc_addr(mb_host *h, const char *name) {
	uintptr_t p = mb_elf_proc_addr(h->elf, name);
	return p ? mb_thunks_get(h->thunks, p, &h->context) : 0;
}
uintptr_t mb_host_proc_addr_raw(mb_host *h, const char *name) { return mb_elf_proc_addr(h->elf, name); }
uintptr_t mb_host_callin_addr(mb_host *h, uintptr_t ptr) { return mb_thunks_get(h->thunks, ptr, &h->context); }

int mb_host_callback_addr(mb_host *h, mb_external_callback cb, uintptr_t slot, uintptr_t *out) {
	if (slot >= MB_CALLBACK_SLOTS) return -1;
	h->context.extcall_slots[slot] = cb;
	*out = mb_get_callback_ptr(slot);
	return 0;
}

int mb_host_seal(mb_host *h, char *errbuf, size_t errlen) {
	if (h->sealed) { snprintf(errbuf, errlen, "Already sealed!"); return -1; }
	bool was_active = h->active;
	mb_host_activate(h);
	run_proc_if_present(h, "co_clean");
	run_proc_if_present(h, "ecl_seal");
	mb_elf_seal(h->elf, h->block);
	if (mb_block_seal(h->block) != 0) { snprintf(errbuf, errlen, "seal failed"); return -1; }
	if (!was_active) mb_host_deactivate(h);
	h->sealed = true;
	return 0;
}

int mb_host_mount(mb_host *h, const char *name, const uint8_t *data, size_t len, bool writable) {
	return mb_fs_mount(h->fs, name, data, len, writable);
}
int mb_host_mount_path(mb_host *h, const char *name, const char *path) {
	return mb_fs_mount_path(h->fs, name, path);
}
int mb_host_unmount(mb_host *h, const char *name, uint8_t **out, size_t *outlen) {
	return mb_fs_unmount(h->fs, name, out, outlen);
}

size_t  mb_host_page_len(mb_host *h) { return mb_block_page_len(h->block); }
uint8_t mb_host_page_info(mb_host *h, size_t i) { return mb_block_page_info(h->block, i); }

/* ---- top-level save/load (structure per docs/docs/MACHINE-SPEC.md section 6) ---- */

static const char SAVE_START[] = "ActivatedWaterboxHost_v1";
/* SAVE_END: the reference's upside-down "ActivatedWaterboxHost" (UTF-8 bytes) */
static const char SAVE_END[] = "\xcb\x87soHxoq\xc9\xaf\xc7\x9d\xca\x87\xc9\x90Mp\xc7\x9d\xca\x87\xc9\x90\xca\x8c\xe1\xb4\x89\xca\x87\xc9\x94\xe2\x88\x80";

static int w_all(mb_write_cb w, uintptr_t ud, const void *d, size_t n) { return w(ud, (const uint8_t *)d, n) < 0 ? -1 : 0; }
static int r_all(mb_read_cb r, uintptr_t ud, void *d, size_t n) {
	uint8_t *p = (uint8_t *)d;
	while (n) { intptr_t g = r(ud, p, n); if (g <= 0) return -1; p += g; n -= (size_t)g; }
	return 0;
}

int mb_host_save_state(mb_host *h, mb_write_cb w, uintptr_t ud, char *errbuf, size_t errlen) {
	if (!h->sealed) { snprintf(errbuf, errlen, "Not sealed!"); return -1; }
	bool was_active = h->active; mb_host_activate(h);
	int rc = -1;
	/* Phase 1 FS is fixed (mounted files only, no per-file dynamic state churn):
	 * the memory block carries all mutable machine state. FS/thread records are
	 * placeholders matching the format's magic framing. */
	if (w_all(w, ud, SAVE_START, sizeof(SAVE_START)-1)) goto done;
	if (w_all(w, ud, "FileSystem", 10) || w_all(w, ud, "FileSystemEnd", 13)) goto done;
	if (w_all(w, ud, &h->program_break, sizeof(h->program_break))) goto done;
	if (w_all(w, ud, "ElfLoader", 9) || w_all(w, ud, mb_elf_hash(h->elf), 32)) goto done;
	if (mb_block_save_state(h->block, w, ud) != 0) goto done;
	if (mb_threads_save(h->threads, &h->context, w, ud) != 0) goto done;
	if (w_all(w, ud, SAVE_END, sizeof(SAVE_END)-1)) goto done;
	rc = 0;
done:
	if (!was_active) mb_host_deactivate(h);
	if (rc) snprintf(errbuf, errlen, "save_state write failed");
	return rc;
}

static int expect(mb_read_cb r, uintptr_t ud, const char *magic, size_t n) {
	char buf[64]; if (n > sizeof(buf)) return -1;
	if (r_all(r, ud, buf, n)) return -1;
	return memcmp(buf, magic, n) == 0 ? 0 : -1;
}

int mb_host_load_state(mb_host *h, mb_read_cb r, uintptr_t ud, char *errbuf, size_t errlen) {
	if (!h->sealed) { snprintf(errbuf, errlen, "Not sealed!"); return -1; }
	bool was_active = h->active; mb_host_activate(h);
	int rc = -1;
	uint8_t elfhash[32];
	if (expect(r, ud, SAVE_START, sizeof(SAVE_START)-1)) { snprintf(errbuf, errlen, "bad start magic"); goto done; }
	if (expect(r, ud, "FileSystem", 10) || expect(r, ud, "FileSystemEnd", 13)) { snprintf(errbuf, errlen, "bad fs magic"); goto done; }
	if (r_all(r, ud, &h->program_break, sizeof(h->program_break))) goto done;
	if (expect(r, ud, "ElfLoader", 9)) { snprintf(errbuf, errlen, "bad elf magic"); goto done; }
	if (r_all(r, ud, elfhash, 32)) goto done;
	if (memcmp(elfhash, mb_elf_hash(h->elf), 32) != 0) { snprintf(errbuf, errlen, "ELF hash mismatch"); goto done; }
	if (mb_block_load_state(h->block, r, ud) != 0) { snprintf(errbuf, errlen, "memory block load failed"); goto done; }
	if (mb_threads_load(h->threads, &h->context, r, ud) != 0) { snprintf(errbuf, errlen, "thread set load failed"); goto done; }
	if (expect(r, ud, SAVE_END, sizeof(SAVE_END)-1)) { snprintf(errbuf, errlen, "bad end magic"); goto done; }
	rc = 0;
done:
	if (!was_active) mb_host_deactivate(h);
	return rc;
}
