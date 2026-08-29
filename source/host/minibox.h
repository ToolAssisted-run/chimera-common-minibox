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
void wbx_set_always_evict_blocks(bool val);
void wbx_get_page_len(mb_host *obj, mb_return *ret);
void wbx_get_page_data(mb_host *obj, uintptr_t index, mb_return *ret);

#ifdef __cplusplus
}
#endif
#endif
