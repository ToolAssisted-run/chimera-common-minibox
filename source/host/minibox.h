/* miniBox runtime - public C ABI. Byte-compatible with the Rust reference's
 * wbx_* surface (BizHawk waterboxhost src/cinterface.rs) and with the managed consumer
 * (managed/WaterboxHostNative.cs), so the same C# layer drives either host.
 *
 * Every fallible call takes a trailing mb_return*: on success error_message[0]
 * is 0 and data holds the result; on failure error_message is a NUL-terminated
 * string and data is unspecified.
 */
#ifndef MINIBOX_H
#define MINIBOX_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct { uint8_t error_message[1024]; uintptr_t data; } mb_return;

/* page-aligned heap sizes; mirrors MemoryLayoutTemplate */
typedef struct { uintptr_t sbrk_size, sealed_size, invis_size, plain_size, mmap_size; } mb_memory_layout_template;

/* n read (0=EOF, <0 fail); may read less than requested but >=1 unless EOF */
typedef intptr_t (*mb_read_callback)(uintptr_t userdata, uint8_t *data, uintptr_t size);
/* 0 ok, <0 fail; must write all requested bytes */
typedef int32_t (*mb_write_callback)(uintptr_t userdata, const uint8_t *data, uintptr_t size);
/* the allowed shape of any guest<->host callback */
/* Called BY THE GUEST through the interop blob, which is always sysv64 - so on a
 * Windows host this must be declared sysv64 explicitly, or the callback reads
 * its arguments from win64 registers the guest never set. (Read/write callbacks
 * passed to wbx_mount_file and friends are called by the HOST and are ordinary
 * host-ABI functions; only this one crosses the guest boundary.) */
#if defined(_WIN32) && defined(__GNUC__)
#define MB_GUEST_ABI __attribute__((sysv_abi))
#else
#define MB_GUEST_ABI
#endif
typedef uintptr_t (MB_GUEST_ABI *mb_external_callback)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

typedef struct mb_host mb_host;

void wbx_create_host(const mb_memory_layout_template *layout, const char *module_name,
                     mb_read_callback cb, uintptr_t userdata, mb_return *ret);
void wbx_destroy_host(mb_host *obj, mb_return *ret);
void wbx_activate_host(mb_host *obj, mb_return *ret);
void wbx_deactivate_host(mb_host *obj, mb_return *ret);
void wbx_get_proc_addr(mb_host *obj, const char *name, mb_return *ret);
void wbx_get_callin_addr(mb_host *obj, uintptr_t ptr, mb_return *ret);
void wbx_get_proc_addr_raw(mb_host *obj, const char *name, mb_return *ret);
/* Registers a host callback the GUEST can call, returning its guest-visible
 * address. The callback MUST be declared MB_GUEST_ABI (see above): it is entered
 * from sysv64 code, and a win64 callee would corrupt the caller's stack with its
 * shadow-space spill. */
void wbx_get_callback_addr(mb_host *obj, mb_external_callback callback, uintptr_t slot, mb_return *ret);
/* The second (since 1970, UTC) the machine's clock starts at; 1495889068
 * (May 27, 2017) when never told. Before the core first runs; refused once
 * the machine is sealed, and for a start later than 2200-01-01. */
void wbx_set_clock_start(mb_host *obj, uint64_t unix_seconds, mb_return *ret);
void wbx_seal(mb_host *obj, mb_return *ret);
void wbx_mount_file(mb_host *obj, const char *name, mb_read_callback cb, uintptr_t userdata, bool writable, mb_return *ret);
/* Mounts a file on the host's disk, read-only, WITHOUT reading it: the guest's
 * reads go to the disk as it makes them. For anything large - a disc image is
 * gigabytes - this is the difference between a copy the machine never needed
 * and no copy at all. The bytes a guest sees are the same as wbx_mount_file's,
 * so nothing about the machine changes; a read-only file has nothing to save,
 * so a savestate does not change either. The file must not change while it is
 * mounted: its length is taken once, at mount. */
void wbx_mount_file_path(mb_host *obj, const char *name, const char *host_path, mb_return *ret);
void wbx_unmount_file(mb_host *obj, const char *name, mb_write_callback cb, uintptr_t userdata, mb_return *ret);
void wbx_save_state(mb_host *obj, mb_write_callback cb, uintptr_t userdata, mb_return *ret);
void wbx_load_state(mb_host *obj, mb_read_callback cb, uintptr_t userdata, mb_return *ret);

/* ---- epochs and deltas ----
 *
 * A savestate carries every page the machine has dirtied since it was sealed,
 * which for a long run is most of the machine every time. An EPOCH asks the
 * smaller question - what changed since this moment - so a caller keeping a
 * history along a timeline can pay for what a frame DID rather than for what
 * the machine IS.
 *
 * wbx_epoch_begin marks now. Afterwards:
 *   wbx_save_delta(forward=true)  the machine as it is now, given the machine
 *                                 as it was at the mark. Play a run forwards.
 *   wbx_save_delta(forward=false) the machine as it was at the mark, given the
 *                                 machine as it is now. Step a frame back.
 * wbx_load_delta applies either, and ends the epoch: the machine has moved and
 * the mark no longer describes it, so the caller marks again when it wants to.
 *
 * A delta is not a savestate and cannot stand alone. It is only meaningful
 * applied to exactly the machine it was measured against; applied to any other
 * it produces nonsense, which is the caller's contract to keep. It carries the
 * ELF hash and the page count, so the grossest mistakes are refused.
 *
 * None of this is visible to the guest - it is host protection bookkeeping, the
 * same trick the baseline dirty tracking already plays - so the machine spec is
 * untouched and no movie is affected. */
void wbx_epoch_begin(mb_host *obj, mb_return *ret);
void wbx_save_delta(mb_host *obj, bool forward, mb_write_callback cb, uintptr_t userdata, mb_return *ret);
void wbx_load_delta(mb_host *obj, mb_read_callback cb, uintptr_t userdata, mb_return *ret);
/* Two forward deltas, the second measured from where the first ended, written
 * out as one delta that spans both. Applying the result lands on exactly the
 * machine applying the pair in order would. Takes no host: a delta is bytes,
 * and this is a transform on them, so a caller can thin a stored history with
 * no machine loaded at all. */
void wbx_compose_delta(mb_read_callback a, uintptr_t a_userdata,
                       mb_read_callback b, uintptr_t b_userdata,
                       mb_write_callback out, uintptr_t out_userdata, mb_return *ret);
/* pages the open epoch has touched: what a delta would cost, before writing one */
void wbx_get_epoch_page_count(mb_host *obj, mb_return *ret);
void wbx_set_always_evict_blocks(bool val);
/* The core log: copy everything any guest writes to stdout/stderr into this
 * file (UTF-8 path, appended, flushed per write) until called with NULL. */
void wbx_set_output_file(const char *path, mb_return *ret);
void wbx_get_page_len(mb_host *obj, mb_return *ret);
/* Whether host code may read (write false) or write the guest's bytes
 * [addr, addr+len): data 1 or 0 - inside its memory, every page allocated and
 * with the access, or protected below it by a guest whose fault handler will
 * be asked. For a frontend that follows a pointer the core handed it, as
 * Chimera's GPU bridge does (2026-10-18). */
void wbx_guest_range_ok(mb_host *obj, uintptr_t addr, uintptr_t len, bool write, mb_return *ret);
/* A pointer for READING the guest's bytes [addr, addr+len) without ever
 * running guest code: ret->data, the same bytes through a second view of the
 * guest's memory that never faults. Read through the guest's own view, a page
 * the guest protected runs its fault handler, which may change the machine
 * (RPCS3's texture cache writes the picture back), so a frontend's memory
 * tools read through this (2026-10-18). A page the guest gave back reads as
 * zeros. Good until the host is destroyed. Never write through it: no fault
 * would tell dirty tracking, and states and the history would miss the write.
 * An error when the range is not the guest's memory, or the OS gives it no
 * memory (Windows, a block over 4 GiB, out of memory). */
void wbx_guest_read_view(mb_host *obj, uintptr_t addr, uintptr_t len, mb_return *ret);
void wbx_get_page_data(mb_host *obj, uintptr_t index, mb_return *ret);
/* Whether the guest has died - aborted, halted, faulted, exited, or asked for
 * something the host does not provide - and why, as one line for a person.
 * ret->data is 1 for a dead machine and 0 for a live one; `out` receives the
 * reason (empty while alive), cut to `cap`. A dead machine returns 0 from
 * every call into it and runs nothing, until wbx_load_state revives it. */
void wbx_get_death(mb_host *obj, char *out, uintptr_t cap, mb_return *ret);
/* Stopping a guest that does not come back (2026-10-19). wbx_stop_from_here
 * names the calling thread as the one that will call into the guest (call it
 * on that thread; again if the thread changes). wbx_stop_guest, from any other
 * thread, asks that the call in progress end: the guest dies, as after a crash,
 * with `why` as the reason (wbx_get_death), at its next system call or at once
 * while it runs its own code. Not while it is in host code: ret->data is 1 when
 * the stop was delivered (Linux: the signal was sent; Windows: the thread was
 * sent out), and asking again later is how a caller waits that out. A call
 * that ended by itself should be followed by wbx_stop_cancel, so a stop asked
 * for too late does not end the next one. A stop is dropped when the guest
 * works after it was asked for (wbx_guest_activity moves): a driver call that
 * took long and came back is not a stuck guest. Asked on the thread running
 * the call (from a host callback), it waits for the guest's next system call. */
void wbx_stop_from_here(mb_host *obj, mb_return *ret);
void wbx_stop_guest(mb_host *obj, const char *why, mb_return *ret);
void wbx_stop_cancel(mb_host *obj, mb_return *ret);
/* A count of the guest's system calls, leaving out those a waiting or polling
 * loop makes (yields, sleeps, clock reads, futexes, thread ids): safe to read
 * from any thread. A watchdog that sees it move knows the guest is working -
 * compiling, loading - and not stuck (2026-10-19). */
void wbx_guest_activity(mb_host *obj, mb_return *ret);
/* A count of the frontend's own work for the guest - its callbacks, a GPU
 * driver call, a compile cache - for wbx_guest_activity to add in. The
 * frontend adds to *counter after each piece of work, on the thread that
 * calls the guest; it must outlive the host. NULL takes it away. */
void wbx_count_work_from(mb_host *obj, const uint64_t *counter, mb_return *ret);

#ifdef __cplusplus
}
#endif
#endif
