/* The exported wbx_* C ABI (BizHawk waterboxhost src/cinterface.rs). Thin wrappers over the
 * host, filling mb_return on success/failure. Byte-compatible with the managed
 * consumer, so the same C# layer drives this host or the Rust one. */
#include "minibox.h"
#include "minibox_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* host.c */
mb_host *mb_host_new(const uint8_t *image, size_t image_len, const char *module_name,
                     const mb_memory_layout_template *tpl, char *errbuf, size_t errlen);
void      mb_host_destroy(mb_host *h);
void      mb_host_activate(mb_host *h);
void      mb_host_deactivate(mb_host *h);
uintptr_t mb_host_proc_addr(mb_host *h, const char *name);
uintptr_t mb_host_proc_addr_raw(mb_host *h, const char *name);
uintptr_t mb_host_callin_addr(mb_host *h, uintptr_t ptr);
int       mb_host_callback_addr(mb_host *h, mb_external_callback cb, uintptr_t slot, uintptr_t *out);
int       mb_host_seal(mb_host *h, char *errbuf, size_t errlen);
int       mb_host_mount(mb_host *h, const char *name, const uint8_t *data, size_t len, bool writable);
int       mb_host_mount_path(mb_host *h, const char *name, const char *path);
int       mb_host_unmount(mb_host *h, const char *name, uint8_t **out, size_t *outlen);
size_t    mb_host_page_len(mb_host *h);
const uint8_t *mb_host_hash(mb_host *h);
uint8_t   mb_host_page_info(mb_host *h, size_t i);
int       mb_host_save_state(mb_host *h, mb_write_callback w, uintptr_t ud, char *errbuf, size_t errlen);
int       mb_host_load_state(mb_host *h, mb_read_callback r, uintptr_t ud, char *errbuf, size_t errlen);
int       mb_host_epoch_begin(mb_host *h, char *errbuf, size_t errlen);
int       mb_host_delta_save(mb_host *h, bool forward, mb_write_callback w, uintptr_t ud, char *errbuf, size_t errlen);
int       mb_host_delta_apply(mb_host *h, mb_read_callback r, uintptr_t ud, char *errbuf, size_t errlen);
int       mb_host_delta_compose(mb_read_callback a, uintptr_t aud, mb_read_callback b, uintptr_t bud,
                                mb_write_callback w, uintptr_t ud, char *errbuf, size_t errlen);
int       mb_host_delta_compose_mem(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
                                    mb_write_callback w, uintptr_t ud, char *errbuf, size_t errlen);
size_t    mb_host_epoch_page_count(const mb_host *h);

static bool g_always_evict = true;

static void ok(mb_return *ret, uintptr_t data) { ret->error_message[0] = 0; ret->data = data; }
static void err(mb_return *ret, const char *msg) {
	size_t n = strlen(msg); if (n > 1023) n = 1023;
	memcpy(ret->error_message, msg, n); ret->error_message[n] = 0;
}

/* Read the whole guest/file stream from a reader into a malloc'd buffer. */
static uint8_t *read_all(mb_read_callback cb, uintptr_t ud, size_t *out_len) {
	size_t cap = 1 << 16, len = 0;
	uint8_t *buf = (uint8_t *)malloc(cap);
	for (;;) {
		if (len == cap) { cap *= 2; buf = (uint8_t *)realloc(buf, cap); }
		intptr_t got = cb(ud, buf + len, cap - len);
		if (got < 0) { free(buf); return NULL; }
		if (got == 0) break;
		len += (size_t)got;
	}
	*out_len = len;
	return buf;
}

void wbx_create_host(const mb_memory_layout_template *layout, const char *module_name,
                     mb_read_callback cb, uintptr_t userdata, mb_return *ret) {
	size_t len = 0;
	uint8_t *image = read_all(cb, userdata, &len);
	if (!image) { err(ret, "failed to read guest image"); return; }
	char e[256]; e[0] = 0;
	mb_host *h = mb_host_new(image, len, module_name ? module_name : "guest", layout, e, sizeof(e));
	free(image);
	if (!h) { err(ret, e[0] ? e : "wbx_create_host failed"); return; }
	ok(ret, (uintptr_t)h);
}

/* What built this host, as JSON. The frontend records it: a run is only reproducible
 * if every binary in the path can say where it came from, and this is the sandbox. */
const char *wbx_build_info(void) { return mb_build_info(); }

void wbx_destroy_host(mb_host *obj, mb_return *ret) { mb_host_destroy(obj); ok(ret, 0); }
void wbx_activate_host(mb_host *obj, mb_return *ret) { mb_host_activate(obj); ok(ret, 0); }
void wbx_deactivate_host(mb_host *obj, mb_return *ret) { mb_host_deactivate(obj); ok(ret, 0); }

void wbx_get_proc_addr(mb_host *obj, const char *name, mb_return *ret) { ok(ret, mb_host_proc_addr(obj, name)); }
void wbx_get_proc_addr_raw(mb_host *obj, const char *name, mb_return *ret) { ok(ret, mb_host_proc_addr_raw(obj, name)); }
void wbx_get_callin_addr(mb_host *obj, uintptr_t ptr, mb_return *ret) { ok(ret, mb_host_callin_addr(obj, ptr)); }

void wbx_get_callback_addr(mb_host *obj, mb_external_callback cb, uintptr_t slot, mb_return *ret) {
	uintptr_t out;
	if (mb_host_callback_addr(obj, cb, slot, &out) != 0) { err(ret, "slot must be < 64"); return; }
	ok(ret, out);
}

void wbx_seal(mb_host *obj, mb_return *ret) {
	char e[256]; e[0] = 0;
	if (mb_host_seal(obj, e, sizeof(e)) != 0) { err(ret, e); return; }
	ok(ret, 0);
}

void wbx_mount_file(mb_host *obj, const char *name, mb_read_callback cb, uintptr_t userdata, bool writable, mb_return *ret) {
	size_t len = 0;
	uint8_t *data = read_all(cb, userdata, &len);
	if (!data) { err(ret, "failed to read file"); return; }
	int rc = mb_host_mount(obj, name, data, len, writable);
	free(data);
	if (rc != 0) { err(ret, "mount failed (already mounted?)"); return; }
	ok(ret, 0);
}

void wbx_mount_file_path(mb_host *obj, const char *name, const char *host_path, mb_return *ret) {
	int rc = mb_host_mount_path(obj, name, host_path);
	if (rc == -EEXIST) { err(ret, "mount failed (already mounted?)"); return; }
	if (rc != 0) { err(ret, "cannot open the file to mount"); return; }
	ok(ret, 0);
}

void wbx_unmount_file(mb_host *obj, const char *name, mb_write_callback cb, uintptr_t userdata, mb_return *ret) {
	uint8_t *data = NULL; size_t len = 0;
	int rc = mb_host_unmount(obj, name, cb ? &data : NULL, &len);
	if (rc != 0) { err(ret, "unmount failed"); return; }
	if (cb && data) cb(userdata, data, len);
	free(data);
	ok(ret, 0);
}

void wbx_save_state(mb_host *obj, mb_write_callback cb, uintptr_t userdata, mb_return *ret) {
	char e[256]; e[0] = 0;
	if (mb_host_save_state(obj, cb, userdata, e, sizeof(e)) != 0) { err(ret, e); return; }
	ok(ret, 0);
}

void wbx_load_state(mb_host *obj, mb_read_callback cb, uintptr_t userdata, mb_return *ret) {
	char e[256]; e[0] = 0;
	if (mb_host_load_state(obj, cb, userdata, e, sizeof(e)) != 0) { err(ret, e); return; }
	ok(ret, 0);
}

void wbx_epoch_begin(mb_host *obj, mb_return *ret) {
	char e[256]; e[0] = 0;
	if (mb_host_epoch_begin(obj, e, sizeof(e)) != 0) { err(ret, e); return; }
	ok(ret, 0);
}

void wbx_save_delta(mb_host *obj, bool forward, mb_write_callback cb, uintptr_t userdata, mb_return *ret) {
	char e[256]; e[0] = 0;
	if (mb_host_delta_save(obj, forward, cb, userdata, e, sizeof(e)) != 0) { err(ret, e); return; }
	ok(ret, 0);
}

void wbx_load_delta(mb_host *obj, mb_read_callback cb, uintptr_t userdata, mb_return *ret) {
	char e[256]; e[0] = 0;
	if (mb_host_delta_apply(obj, cb, userdata, e, sizeof(e)) != 0) { err(ret, e); return; }
	ok(ret, 0);
}

void wbx_compose_delta(mb_read_callback a, uintptr_t a_userdata,
                       mb_read_callback b, uintptr_t b_userdata,
                       mb_write_callback out, uintptr_t out_userdata, mb_return *ret) {
	char e[256]; e[0] = 0;
	if (mb_host_delta_compose(a, a_userdata, b, b_userdata, out, out_userdata, e, sizeof(e)) != 0) { err(ret, e); return; }
	ok(ret, 0);
}

/* Composing two deltas the caller already holds in memory, which is what the
 * history does every frame. The same answer as wbx_compose_delta for a third of
 * the memory traffic; a frontend that does not find this export falls back to
 * that one. */
void wbx_compose_delta_mem(const uint8_t *a, uintptr_t a_len, const uint8_t *b, uintptr_t b_len,
                           mb_write_callback out, uintptr_t out_userdata, mb_return *ret) {
	char e[256]; e[0] = 0;
	if (mb_host_delta_compose_mem(a, (size_t)a_len, b, (size_t)b_len, out, out_userdata, e, sizeof(e)) != 0) {
		err(ret, e); return;
	}
	ok(ret, 0);
}

void wbx_get_epoch_page_count(mb_host *obj, mb_return *ret) { ok(ret, mb_host_epoch_page_count(obj)); }

void wbx_set_always_evict_blocks(bool val) { g_always_evict = val; (void)g_always_evict; }

void wbx_get_page_len(mb_host *obj, mb_return *ret) { ok(ret, mb_host_page_len(obj)); }

/* The sealed machine's identity, 32 bytes, copied into the caller's buffer.
 * A caller that CACHES states across sessions needs this: two boots of one core
 * with one configuration can still seal differently - they touched different
 * pages getting there - and states do not cross that line. Without it the only
 * warning is a refused load somewhere far from where the cache was trusted. */
void wbx_machine_hash(mb_host *obj, uint8_t *out, mb_return *ret) {
	if (out == NULL) { err(ret, "no buffer"); return; }
	memcpy(out, mb_host_hash(obj), 32);
	ok(ret, 32);
}
void wbx_get_page_data(mb_host *obj, uintptr_t index, mb_return *ret) {
	if (index >= mb_host_page_len(obj)) { err(ret, "Index out of range"); return; }
	ok(ret, mb_host_page_info(obj, index));
}
