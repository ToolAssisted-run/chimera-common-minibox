/* miniBox runtime (C port) - internal types and constants.
 * Phase 1: Linux x86-64, single guest thread, C guests. Faithful to
 * MACHINE-SPEC.md and to the machine spec (docs/MACHINE-SPEC.md); the Rust original is in BizHawk's waterboxhost.
 *
 * Derived from BizHawk's waterboxhost (MIT). See ../LICENSE, ../ATTRIBUTION.md.
 */
#ifndef MINIBOX_INTERNAL_H
#define MINIBOX_INTERNAL_H

#include "minibox.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* The guest ABI's signed word. It has to be 64-bit everywhere: Linux is LP64 so
 * `long` was fine, but Windows is LLP64 where `long` is 32 bits - and a guest
 * address like 0x36f0020b000 passed back through one comes out as 0x20b000. That
 * is not a subtle bug: brk returned a truncated break, the guest computed its
 * next break from it, and the process died inside the first file read. */
typedef intptr_t mb_sword;
/* If this ever fails, every syscall return is silently losing its top half. */
typedef char mb_sword_is_64_bit[sizeof(mb_sword) == 8 ? 1 : -1];


#define MB_PAGESIZE 0x1000u
#define MB_PAGEMASK 0xfffu
#define MB_PAGESHIFT 12

static inline uintptr_t mb_align_down(uintptr_t p) { return p & ~(uintptr_t)MB_PAGEMASK; }
static inline uintptr_t mb_align_up(uintptr_t p)   { return ((p - 1) | MB_PAGEMASK) + 1; }

/* A half-open address range [start, start+size). */
typedef struct { uintptr_t start; uintptr_t size; } mb_range;
static inline uintptr_t mb_range_end(mb_range r) { return r.start + r.size; }
static inline bool mb_range_contains(mb_range r, uintptr_t a) { return a >= r.start && a < mb_range_end(r); }
static inline mb_range mb_range_align_expand(mb_range r) {
	mb_range o; o.start = mb_align_down(r.start); o.size = mb_align_up(mb_range_end(r)) - o.start; return o;
}

/* Memory layout injected into the guest via __wbxsysinfo. Keep in sync with
 * emulibc's __WbxSysLayout and the Rust WbxSysLayout (8 {u64 start,u64 size}). */
typedef struct {
	mb_range elf, main_thread, alt_thread, sbrk, sealed, invis, plain, mmap_arena;
} mb_layout;
static inline mb_range mb_layout_all(const mb_layout *l) {
	mb_range r; r.start = l->elf.start; r.size = mb_range_end(l->mmap_arena) - l->elf.start; return r;
}

/* Host-supplied heap sizes (bytes, page-aligned). Mirrors MemoryLayoutTemplate. */
typedef struct { uintptr_t sbrk_size, sealed_size, invis_size, plain_size, mmap_size; } mb_layout_template;

/* Guest-visible protection of an allocated page. */
typedef enum { MB_PROT_NONE, MB_PROT_R, MB_PROT_RW, MB_PROT_RX, MB_PROT_RWX, MB_PROT_RWSTACK } mb_prot;

/* ---- PAL (pal_linux.c / pal_win.c): thin wrappers over the OS. Ranges aligned. ---- */
typedef struct {
	uintptr_t h;   /* memfd (Linux) or file mapping HANDLE (Windows) */
	bool lazy;     /* Windows, blocks over 4 GiB: the section is reserved, not
	                  committed; memblock commits page runs before first use */
} mb_handle;
int      mb_pal_open_handle(uintptr_t size, mb_handle *out);   /* 0 ok */
void     mb_pal_close_handle(mb_handle h);
/* map_handle: start==0 -> OS chooses; else fixed. Returns actual range, no access. */
int      mb_pal_map_handle(mb_handle h, mb_range in, mb_range *out);
void     mb_pal_unmap_handle(mb_range addr);
int      mb_pal_map_anon(mb_range in, mb_prot prot, mb_range *out);
void     mb_pal_unmap_anon(mb_range addr);
int      mb_pal_protect(mb_range addr, mb_prot prot);          /* 0 ok */
/* Lazy blocks (handle.lazy): back a range of a reserved section with the given
 * protection. On Linux nothing is ever lazy and this is mprotect. */
int      mb_pal_commit(mb_range addr, mb_prot prot);           /* 0 ok */
/* Windows only (no-op elsewhere): query one region's guard-page dirtiness for
 * RWStack tracking. Returns the region size in *out_size and whether it's dirty
 * (guard bit cleared). Returns 0 on success. */
int      mb_pal_get_stack_dirty(uintptr_t start, uintptr_t *out_size, bool *out_dirty);

/* ---- sha256.c ---- */
typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t fill; } mb_sha256;
void mb_sha256_init(mb_sha256 *c);
void mb_sha256_update(mb_sha256 *c, const void *data, size_t n);
void mb_sha256_final(mb_sha256 *c, uint8_t out[32]);

/* ---- Stream callbacks (match the wbx ReadCallback/WriteCallback ABI) ---- */
typedef intptr_t (*mb_read_cb)(uintptr_t userdata, uint8_t *data, uintptr_t size);
typedef int32_t  (*mb_write_cb)(uintptr_t userdata, const uint8_t *data, uintptr_t size);

/* ---- Memory block (memblock.c) ---- */
typedef enum { MB_SNAP_NONE, MB_SNAP_ZERO, MB_SNAP_DATA } mb_snap_kind;
typedef struct {
	uint8_t status;      /* MB_ST_* below (Free) or MB_ST_ALLOC | (prot+1) */
	bool dirty;
	bool invisible;
	mb_snap_kind snap_kind;
	uint8_t *snap_data;  /* MB_PAGESIZE bytes when snap_kind==DATA, else NULL */
	bool uncommitted;    /* lazy blocks only: neither view is backed yet (reads as zero) */
} mb_page;

/* status byte encoding (also what page_info reports, minus dirty/invis bits) */
#define MB_ST_FREE      0x00
#define MB_ST_NONE      0x20  /* allocated, no access (guard) */
#define MB_ST_R         0x01
#define MB_ST_RW        0x03
#define MB_ST_RX        0x05
#define MB_ST_RWX       0x07
#define MB_ST_RWSTACK   0x13

typedef struct mb_block {
	mb_page *pages;
	size_t npages;
	mb_range addr;       /* fixed guest address range */
	mb_range mirror;     /* always-RW second mapping, OS-chosen */
	bool sealed;
	bool swapped_in;
	bool active;
	uint8_t hash[32];
	mb_handle handle;
} mb_block;

mb_block *mb_block_new(mb_range addr);
void      mb_block_free(mb_block *b);
void      mb_block_activate(mb_block *b);
void      mb_block_deactivate(mb_block *b);

/* syscall-shaped memory ops; return 0 on success or -errno. */
int  mb_block_mmap_fixed(mb_block *b, mb_range addr, mb_prot prot, bool no_replace);
mb_sword mb_block_mmap(mb_block *b, mb_range addr, mb_prot prot, mb_range arena, bool no_replace); /* addr or -errno */
int  mb_block_mprotect(mb_block *b, mb_range addr, mb_prot prot);
int  mb_block_munmap(mb_block *b, mb_range addr);
int  mb_block_madvise_dontneed(mb_block *b, mb_range addr);
mb_sword mb_block_mremap(mb_block *b, mb_range addr, uintptr_t new_size, mb_range arena);
int  mb_block_mark_invisible(mb_block *b, mb_range addr);
int  mb_block_copy_from_external(mb_block *b, const uint8_t *src, uintptr_t start, uintptr_t len);
int  mb_block_seal(mb_block *b);

size_t  mb_block_page_len(const mb_block *b);
uint8_t mb_block_page_info(const mb_block *b, size_t index);

/* Savestate (structure per docs/docs/MACHINE-SPEC.md section 6). Return 0 on success. */
int mb_block_save_state(mb_block *b, mb_write_cb w, uintptr_t ud);
int mb_block_load_state(mb_block *b, mb_read_cb r, uintptr_t ud);

/* ---- tripguard.c ---- */
void mb_tripguard_register(mb_block *b);
/* GuestFaultHandler(addr, is_write) -> nonzero when handled; see tripguard.c */
/* Called at its RAW guest address in the guest ABI, on the guest's own
 * thread, from inside the fault handler: the host-to-guest adapter is for a
 * host thread entering the guest, and this thread is already in it. */
typedef int (MB_GUEST_ABI *mb_guest_fault_fn)(uint64_t addr, uint64_t is_write);
void mb_tripguard_set_guest_fault_handler(mb_guest_fault_fn fn);
#ifndef _WIN32
void mb_tripguard_ensure_altstack(void);  /* per-thread; see tripguard.c */
#endif
void mb_tripguard_unregister(mb_block *b);

/* ---- context.c: host<->guest transitions (interop.bin at 0x35f00000000) ---- */
#define MB_ORG            0x35f00000000ull
#define MB_CALLBACK_SLOTS 64

/* The interop blob and the guest are ALWAYS sysv64, whatever the host is. On a
 * Windows host, every function pointer that the blob calls, or that calls into
 * the blob, therefore has to be declared sysv64 explicitly - the compiler would
 * otherwise use the win64 ABI and pass arguments in the wrong registers, which
 * shows up as a page fault the first time a guest actually runs. On Linux this
 * expands to nothing, since sysv64 is already the default. */
#ifdef _WIN32
#define MB_SYSV __attribute__((sysv_abi))
#else
#define MB_SYSV
#endif
/* Layout synced with BizHawk waterboxhost src/context/interop.s (struc Context). */
typedef uintptr_t (MB_SYSV *mb_syscall_cb)(uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
                                   uintptr_t a5, uintptr_t a6, uintptr_t nr, void *host);
typedef struct {
	uintptr_t thread_area, host_rsp, guest_rsp, host_rsp_alt, guest_rsp_alt;
	mb_syscall_cb dispatch_syscall;
	uintptr_t host_ptr;
	mb_external_callback extcall_slots[MB_CALLBACK_SLOTS];
	/* The host thread's real %fs (glibc TLS base), stored by the guest-entry
	 * paths so the syscall dispatcher can restore it. A Rust guest uses
	 * %fs-direct TLS, so %fs holds the GUEST thread pointer (thread_area) while
	 * guest code runs and must be swapped back to host_fs for host C at the
	 * syscall boundary. Trailing field: the interop blob only knows the fields
	 * above it, so appending here changes no interop offset. */
	uintptr_t host_fs;
	/* Swap %fs around guest execution? Only for a guest that carries PT_TLS,
	 * i.e. one whose toolchain emits %fs-relative TLS (Rust). C/C++ guests on
	 * the waterbox musl reach their thread pointer through %gs and must be left
	 * strictly alone - swapping for them would buy nothing and would put host
	 * callbacks on the guest's %fs (see docs: the extcall path is NOT covered).
	 * Read by the syscall dispatcher as a plain load, before any call. */
	bool fs_swap;
} mb_context;

/* Single-instruction %fs swaps (FSGSBASE). The guest and host share the CPU
 * thread; a Rust guest needs %fs = its thread pointer (mb_context.thread_area)
 * while host C needs %fs = mb_context.host_fs.
 *
 * x86-64, and only where the OS exposes FSGSBASE to userspace - the
 * instructions fault otherwise, which would break every C/C++ guest too, so
 * everything is gated on the one-time probe (mb_fsbase_ok).
 *
 * Windows is the easier of the two, not the harder: its own thread block is at
 * %gs (the TEB), so %fs is nobody's there and the swap cannot tread on the
 * host's toes. The probe is still required, because whether user mode may run
 * rdfsbase at all is the OS's decision. */
#if defined(__x86_64__) || defined(__amd64__)
#define MB_HAVE_FSBASE 1
/* The "memory" clobber is load-bearing, not decoration: without it the compiler
 * may sink or hoist the swap across the calls it is meant to bracket, and host
 * glibc running for even one call against the guest's TLS corrupts guest memory
 * (it shows up much later as the guest's own malloc returning a bad pointer). */
static inline uintptr_t mb_rdfsbase(void) { uintptr_t v; __asm__ volatile("rdfsbase %0" : "=r"(v) :: "memory"); return v; }
static inline void mb_wrfsbase(uintptr_t v) { __asm__ volatile("wrfsbase %0" :: "r"(v) : "memory"); }
bool mb_fsbase_ok(void);
/* Plain global, not a call: the dispatcher must decide whether to swap BEFORE
 * it may safely call anything (it is entered on the guest's %fs). */
extern bool mb_fs_swap;
#endif

void      mb_context_init(mb_context *c, uintptr_t guest_rsp, uintptr_t guest_rsp_alt, mb_syscall_cb dispatch);
void      mb_prepare_thread(void);              /* install gs base once per host thread */
uintptr_t mb_call_guest_simple(uintptr_t entry, mb_context *c);
uintptr_t mb_get_callback_ptr(uintptr_t slot); /* fixed extcall thunk address */

/* thunk manager: RWX stubs wrapping guest entries with the stack-switch call-in */
typedef struct mb_thunks mb_thunks;
mb_thunks *mb_thunks_new(void);
void       mb_thunks_free(mb_thunks *t);
uintptr_t  mb_thunks_get(mb_thunks *t, uintptr_t guest_entry, mb_context *c);
/* A host callback the guest may call, wrapped so the host's %fs is back in
 * place before any host code runs. Returns cb unchanged when no swap is on. */
uintptr_t  mb_thunks_get_extcall(mb_thunks *t, uintptr_t cb, mb_context *c);

/* ---- elf.c ---- */
typedef struct mb_elf mb_elf;
/* parse+load the guest image into b; fills *out. Returns 0 on success. */
int       mb_elf_load(const uint8_t *image, size_t image_len, const char *module_name,
                      const mb_layout *layout, mb_block *b, mb_elf **out);
void      mb_elf_free(mb_elf *e);
uintptr_t mb_elf_entry(const mb_elf *e);
bool      mb_elf_has_tls(const mb_elf *e); /* guest carries PT_TLS -> needs %fs swapping */
uintptr_t mb_elf_proc_addr(const mb_elf *e, const char *name); /* 0 if absent */
void      mb_elf_seal(mb_elf *e, mb_block *b);   /* mprotect RO sections */
const uint8_t *mb_elf_hash(const mb_elf *e);     /* 32 bytes */
mb_range  mb_elf_span(const uint8_t *image, size_t image_len); /* PT_LOAD span */

/* ---- fs.c ---- */
typedef struct mb_fs mb_fs;
mb_fs *mb_fs_new(void);
void   mb_fs_free(mb_fs *fs);
int    mb_fs_mount(mb_fs *fs, const char *name, const uint8_t *data, size_t len, bool writable);
/* read-only, read on demand from the host's disk; nothing is copied */
int    mb_fs_mount_path(mb_fs *fs, const char *name, const char *path);
int    mb_fs_unmount(mb_fs *fs, const char *name, uint8_t **out_data, size_t *out_len); /* caller frees */
/* syscall-shaped ops: return value or -errno */
mb_sword mb_fs_open(mb_fs *fs, const char *name, int flags);
mb_sword mb_fs_close(mb_fs *fs, int fd);
mb_sword mb_fs_read(mb_fs *fs, int fd, uint8_t *buf, size_t n);
mb_sword mb_fs_write(mb_fs *fs, int fd, const uint8_t *buf, size_t n);
mb_sword mb_fs_seek(mb_fs *fs, int fd, mb_sword offset, int whence);
mb_sword mb_fs_stat_name(mb_fs *fs, const char *name, void *kstat);
mb_sword mb_fs_stat_fd(mb_fs *fs, int fd, void *kstat);
mb_sword mb_fs_truncate_name(mb_fs *fs, const char *name, mb_sword size);
mb_sword mb_fs_truncate_fd(mb_fs *fs, int fd, mb_sword size);

/* Internal helpers shared with tripguard (memblock.c). */
mb_prot mb_page_native_prot(const mb_page *p);
void    mb_page_maybe_snapshot(mb_page *p, uintptr_t mirror_addr);

/* ---- diagnostics (diag.c) ----
 * For the last words of a dying sandbox. Goes to stderr AND to a file, because a
 * host loaded into a GUI process has no stderr and "it vanished" is not a bug
 * report. Fatal paths only: no file is written during a healthy run. */
void    mb_diag(const char *fmt, ...);

/// JSON describing what built this library (see diag.c). Exported as wbx_build_info.
const char *mb_build_info(void);
void    mb_diag_banner(const char *what);

#endif
