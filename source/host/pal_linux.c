/* Platform abstraction layer, Linux x86-64. Mirrors BizHawk waterboxhost src/memory_block/pal.rs
 * (the nix module). Not meant for general consumption - minimal checking. */
#ifndef _WIN32
#define _GNU_SOURCE
#include "minibox_internal.h"
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 1U
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static int prot_to_native(mb_prot prot) {
	switch (prot) {
		case MB_PROT_NONE:    return PROT_NONE;
		case MB_PROT_R:       return PROT_READ;
		case MB_PROT_RW:      return PROT_READ | PROT_WRITE;
		case MB_PROT_RX:      return PROT_READ | PROT_EXEC;
		case MB_PROT_RWX:     return PROT_READ | PROT_WRITE | PROT_EXEC;
		case MB_PROT_RWSTACK: return PROT_READ | PROT_WRITE; /* linux: RWStack resolved to R/RW before here */
		case MB_PROT_RWGUARD: return PROT_READ; /* windows-only; never asked for here */
	}
	return PROT_NONE;
}

int mb_pal_open_handle(uintptr_t size, mb_handle *out) {
	int fd = (int)syscall(SYS_memfd_create, "MiniBoxBlock", MFD_CLOEXEC);
	if (fd == -1) return -1;
	if (ftruncate(fd, (off_t)size) != 0) { close(fd); return -1; }
	out->h = (uintptr_t)fd;
	out->lazy = false;
	return 0;
}

void mb_pal_close_handle(mb_handle h) { if ((int)h.h >= 0) close((int)h.h); }

int mb_pal_map_handle(mb_handle h, mb_range in, mb_range *out) {
	int flags = MAP_SHARED;
	if (in.start != 0) flags |= MAP_FIXED | MAP_FIXED_NOREPLACE;
	void *p = mmap((void *)in.start, in.size, PROT_NONE, flags, (int)h.h, 0);
	if (p == MAP_FAILED) return -1;
	out->start = (uintptr_t)p;
	out->size = in.size;
	return 0;
}

void mb_pal_unmap_handle(mb_range addr) { munmap((void *)addr.start, addr.size); }

int mb_pal_map_anon(mb_range in, mb_prot prot, mb_range *out) {
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	if (in.start != 0) flags |= MAP_FIXED | MAP_FIXED_NOREPLACE;
	void *p = mmap((void *)in.start, in.size, prot_to_native(prot), flags, -1, 0);
	if (p == MAP_FAILED) return -1;
	out->start = (uintptr_t)p;
	out->size = in.size;
	return 0;
}

void mb_pal_unmap_anon(mb_range addr) { munmap((void *)addr.start, addr.size); }

int mb_pal_protect(mb_range addr, mb_prot prot) {
	return mprotect((void *)addr.start, addr.size, prot_to_native(prot));
}

int mb_pal_commit(mb_range addr, mb_prot prot) {
	return mprotect((void *)addr.start, addr.size, prot_to_native(prot));
}

/* Linux: RWStack uses the fault handler, so no guard-page sweep is needed. */
int mb_pal_get_stack_dirty(uintptr_t start, uintptr_t *out_size, bool *out_dirty) {
	(void)start; *out_size = MB_PAGESIZE; *out_dirty = true; return 0;
}
#endif
