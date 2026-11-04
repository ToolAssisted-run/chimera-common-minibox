/* Platform abstraction layer, macOS x86-64. pal_linux.c's interface, on Mach.
 *
 * A block is ONE set of pages seen twice: at the guest's fixed address,
 * protection-managed, and at the host's always-writable mirror. Linux makes
 * that a memfd mapped twice. macOS has no memfd, and a view of shared memory
 * that has been writable will not later run code, so the "handle" here is a
 * first view nobody touches, which owns the pages, and every view mapped
 * from it is a mach_vm_remap of it (copy = FALSE): both views see every
 * write, and each has a protection of its own. Measured on macOS 27 under
 * Rosetta 2: a write through one view is seen by the other, and a view made
 * RX runs what the other view wrote. */
#if defined(__APPLE__)
#include "minibox_internal.h"
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

static int prot_to_native(mb_prot prot) {
	switch (prot) {
		case MB_PROT_NONE:    return PROT_NONE;
		case MB_PROT_R:       return PROT_READ;
		case MB_PROT_RW:      return PROT_READ | PROT_WRITE;
		case MB_PROT_RX:      return PROT_READ | PROT_EXEC;
		case MB_PROT_RWX:     return PROT_READ | PROT_WRITE | PROT_EXEC;
		case MB_PROT_RWSTACK: return PROT_READ | PROT_WRITE;
	}
	return PROT_NONE;
}

/* A view of [src, src + size) at `at` (0: anywhere), sharing its pages. A
 * fixed address that is not free fails, as MAP_FIXED_NOREPLACE does. */
static int remap(uintptr_t src, uintptr_t size, uintptr_t at, uintptr_t *out) {
	mach_vm_address_t dst = at;
	vm_prot_t cur, max;
	const int flags = at != 0 ? VM_FLAGS_FIXED : VM_FLAGS_ANYWHERE;
	if (mach_vm_remap(mach_task_self(), &dst, size, 0, flags, mach_task_self(),
	                  src, FALSE, &cur, &max, VM_INHERIT_NONE) != KERN_SUCCESS)
		return -1;
	*out = (uintptr_t)dst;
	return 0;
}

/* Where each handle's owning view is, and how big: mb_handle carries one word,
 * so the size rides in a small header page before the view. */
int mb_pal_open_handle(uintptr_t size, mb_handle *out) {
	/* the first page of the mapping holds the size; the pages follow it */
	uint8_t *p = mmap(NULL, size + MB_PAGESIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (p == MAP_FAILED) return -1;
	*(uintptr_t *)p = size;
	out->h = (uintptr_t)(p + MB_PAGESIZE);
	out->lazy = false;
	out->pieces = false;
	return 0;
}

static uintptr_t handle_size(mb_handle h) { return *(uintptr_t *)(h.h - MB_PAGESIZE); }

void mb_pal_close_handle(mb_handle h) {
	if (h.h) munmap((void *)(h.h - MB_PAGESIZE), handle_size(h) + MB_PAGESIZE);
}

int mb_pal_map_handle(mb_handle h, mb_range in, mb_range *out) {
	uintptr_t at;
	if (remap(h.h, in.size, in.start, &at) != 0) return -1;
	if (mprotect((void *)at, in.size, PROT_NONE) != 0) { munmap((void *)at, in.size); return -1; }
	out->start = at;
	out->size = in.size;
	return 0;
}

void mb_pal_unmap_handle(mb_handle h, mb_range addr) { (void)h; munmap((void *)addr.start, addr.size); }

int mb_pal_map_anon(mb_range in, mb_prot prot, mb_range *out) {
	/* a fixed address is a hint mmap may decline; declined is failed, as
	 * Linux's MAP_FIXED_NOREPLACE fails */
	void *p = mmap((void *)in.start, in.size, prot_to_native(prot), MAP_PRIVATE | MAP_ANON, -1, 0);
	if (p == MAP_FAILED) return -1;
	if (in.start != 0 && (uintptr_t)p != in.start) { munmap(p, in.size); errno = EEXIST; return -1; }
	out->start = (uintptr_t)p;
	out->size = in.size;
	return 0;
}

void mb_pal_unmap_anon(mb_range addr) { munmap((void *)addr.start, addr.size); }

/* Tests: how many protection changes to refuse (pal_linux.c's counter). */
int mb_pal_protect_refusals = 0;

int mb_pal_protect(mb_range addr, mb_prot prot) {
	if (mb_pal_protect_refusals > 0) { mb_pal_protect_refusals--; errno = ENOMEM; return -1; }
	return mprotect((void *)addr.start, addr.size, prot_to_native(prot));
}

int mb_pal_commit(mb_handle h, mb_range addr, mb_prot prot) {
	(void)h;
	return mprotect((void *)addr.start, addr.size, prot_to_native(prot));
}

/* Nothing can be handed back page by page and read as zeros in every view:
 * the caller writes zeros (as it does for a Windows block that is not made of
 * pieces). */
uintptr_t mb_pal_release_unit(mb_handle h) { (void)h; return 0; }
int mb_pal_release(mb_handle h, uintptr_t offset, uintptr_t len) { (void)h; (void)offset; (void)len; return -1; }

#endif
