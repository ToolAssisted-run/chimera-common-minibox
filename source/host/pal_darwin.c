/* Platform abstraction layer, macOS, on x86-64 and on Apple silicon.
 * pal_linux.c's interface, on Mach.
 *
 * A block is ONE set of pages seen twice: at the guest's fixed address,
 * where it runs, and wherever the host keeps its own view. On Linux that is
 * a memfd mapped twice. macOS has no memfd, and will not run code from a view
 * of shared memory that has ever been writable anywhere (mprotect to RX
 * answers EACCES, measured on macOS 27), and guest code is exactly that. So
 * the "handle" here is a first view nobody touches, which owns the pages,
 * and every view mapped from it is a mach_vm_remap of it (copy = FALSE): both
 * views see every write, and each has a protection of its own. Measured on
 * macOS 27, natively on Apple silicon and under Rosetta 2: a write through
 * one view is seen by the other, and a view made RX runs what the other view
 * wrote.
 *
 * On Apple silicon nothing is ever writable and executable at once: mmap and
 * mprotect refuse PROT_WRITE|PROT_EXEC outside MAP_JIT memory, and MAP_JIT
 * memory cannot be placed at a fixed address or remapped. Code the host
 * writes at run time (the thunks) is therefore written through a second,
 * writable view (mb_pal_map_code), on both CPUs, so that the two Macs run the
 * same way; guest pages the guest asks to be RWX are memblock's business (see
 * mb_page_native_prot). */
#if defined(__APPLE__)
#include "minibox_internal.h"
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

static int prot_to_native(mb_prot prot) {
	switch (prot) {
		case MB_PROT_NONE:    return PROT_NONE;
		case MB_PROT_R:       return PROT_READ;
		case MB_PROT_RW:      return PROT_READ | PROT_WRITE;
		case MB_PROT_RX:      return PROT_READ | PROT_EXEC;
		case MB_PROT_RWX:     return PROT_READ | PROT_WRITE | PROT_EXEC;   /* refused on Apple silicon */
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
 * so the size rides in a header page before the view.
 *
 * The header is one of the OS's pages, not one of the machine's: on Apple
 * silicon a page is 16 KiB, and with a 4 KiB header the view began inside a
 * page. A view mapped from there (mb_pal_map_handle) starts where that page
 * does, 4 KiB early, so the guest's first bytes were the header: a write at
 * the block's start changed the size, and closing the handle then unmapped
 * memory that was not its own - malloc's among it, which the kernel reads,
 * and macOS killed the process for that (vm_reclaim, "copy I/O error"). */
static uintptr_t header_size(void) { return (uintptr_t)getpagesize(); }

int mb_pal_open_handle(uintptr_t size, mb_handle *out) {
	/* the first page of the mapping holds the size; the pages follow it */
	uint8_t *p = mmap(NULL, size + header_size(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (p == MAP_FAILED) return -1;
	*(uintptr_t *)p = size;
	out->h = (uintptr_t)(p + header_size());
	out->lazy = false;
	out->pieces = false;
	return 0;
}

static uintptr_t handle_size(mb_handle h) { return *(uintptr_t *)(h.h - header_size()); }

void mb_pal_close_handle(mb_handle h) {
	if (h.h) munmap((void *)(h.h - header_size()), handle_size(h) + header_size());
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

/* Code the host writes and the guest runs: one set of pages, an RX view to
 * run and an RW view to write (pal_linux.c's gives one RWX view as both). */
int mb_pal_map_code(uintptr_t size, mb_range *exec, mb_range *write) {
	mb_range in = { 0, size };
	if (mb_pal_map_anon(in, MB_PROT_RW, write) != 0) return -1;
	uintptr_t at;
	if (remap(write->start, size, 0, &at) != 0) { mb_pal_unmap_anon(*write); return -1; }
	if (mprotect((void *)at, size, PROT_READ | PROT_EXEC) != 0) {
		munmap((void *)at, size);
		mb_pal_unmap_anon(*write);
		return -1;
	}
	exec->start = at;
	exec->size = size;
	return 0;
}

void mb_pal_unmap_code(mb_range exec, mb_range write) {
	munmap((void *)exec.start, exec.size);
	munmap((void *)write.start, write.size);
}

#endif
