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
void wbx_get_page_len(mb_host *obj, mb_return *ret);
void wbx_get_page_data(mb_host *obj, uintptr_t index, mb_return *ret);

#ifdef __cplusplus
}
#endif
#endif
