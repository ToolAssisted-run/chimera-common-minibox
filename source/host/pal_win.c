/* Platform abstraction layer, Windows x86-64. Mirrors BizHawk waterboxhost src/memory_block/
 * pal.rs (the win module). CROSS-COMPILE-CHECKED with mingw-w64; not
 * runtime-validated on Linux. */
#ifdef _WIN32
#include "minibox_internal.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/* MB_STACK_GUARD=0 takes the guard bit off clean stack pages.
 *
 * A clean stack page is PAGE_GUARD here and merely read-only on Linux, and the
 * guard bit is what makes stack dirtiness free: the first write trips it and
 * the kernel clears it, so get_stack_dirty can read the answer back later.
 * The cost is that the page is a trap for anything that writes to the stack
 * WITHOUT the process being able to take an exception - and delivering an
 * exception is exactly that, because the kernel pushes the context record onto
 * the faulting thread's own stack. A guest that faults often (a dirty-page trip
 * per page of a large memset) with a stack pointer close to a clean page dies
 * with no handler ever running.
 *
 * Without the guard, stack pages read back as dirty always: states carry more
 * bytes and nothing else changes. */
static bool guard_stacks(void) {
	static int cached = -1;
	if (cached < 0) {
		const char *v = getenv("MB_STACK_GUARD");
		cached = (v != NULL && v[0] == '0') ? 0 : 1;
	}
	return cached != 0;
}

static uint32_t prot_to_native(mb_prot prot) {
	switch (prot) {
		case MB_PROT_NONE:    return PAGE_NOACCESS;
		case MB_PROT_R:       return PAGE_READONLY;
		case MB_PROT_RW:      return PAGE_READWRITE;
		case MB_PROT_RX:      return PAGE_EXECUTE_READ;
		case MB_PROT_RWX:     return PAGE_EXECUTE_READWRITE;
		case MB_PROT_RWSTACK: return PAGE_READWRITE | (guard_stacks() ? PAGE_GUARD : 0);
	}
	return PAGE_NOACCESS;
}

int mb_pal_open_handle(uintptr_t size, mb_handle *out) {
	/* A pagefile-backed section charges its whole size to the commit limit at
	 * creation, and a block spanning many 4 GiB regions (the PS3 core declares
	 * 20 GiB) fits no ordinary pagefile. Such blocks are reserved (SEC_RESERVE)
	 * and backed run by run as the guest maps pages (memblock's
	 * ensure_committed, through mb_pal_commit); blocks up to 4 GiB keep the
	 * eager path every shipped core has run on. */
	bool lazy = size > ((uintptr_t)4 << 30);
	HANDLE m = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
	                              PAGE_EXECUTE_READWRITE | (lazy ? SEC_RESERVE : 0),
	                              (DWORD)(size >> 32), (DWORD)size, NULL);
	if (m == NULL) return -1;
	out->h = (uintptr_t)m;
	out->lazy = lazy;
	return 0;
}

void mb_pal_close_handle(mb_handle h) { CloseHandle((HANDLE)h.h); }

int mb_pal_map_handle(mb_handle h, mb_range in, mb_range *out) {
	void *p = MapViewOfFileEx((HANDLE)h.h, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE,
	                          0, 0, in.size, (void *)in.start);
	if (p == NULL) return -1;
	out->start = (uintptr_t)p;
	out->size = in.size;
	/* map_handle returns no-access memory; protect explicitly like the reference */
	DWORD old;
	VirtualProtect(p, in.size, PAGE_NOACCESS, &old);
	return 0;
}

void mb_pal_unmap_handle(mb_range addr) { UnmapViewOfFile((void *)addr.start); }

int mb_pal_map_anon(mb_range in, mb_prot prot, mb_range *out) {
	void *p = VirtualAlloc((void *)in.start, in.size, MEM_RESERVE | MEM_COMMIT, prot_to_native(prot));
	if (p == NULL) {
		/* Callers abort on failure, and an aborting GUI process leaves the user
		 * with an instant silent exit. Say what failed before that happens: the
		 * address, the size, and what Windows thought of it. */
		MEMORY_BASIC_INFORMATION mbi;
		DWORD err = GetLastError();
		if (in.start && VirtualQuery((void *)in.start, &mbi, sizeof mbi)) {
			fprintf(stderr, "miniBox: VirtualAlloc(%p, %llu) failed, error %lu "
			                "(that address is currently state=%lx protect=%lx type=%lx)\n",
			        (void *)in.start, (unsigned long long)in.size, (unsigned long)err,
			        (unsigned long)mbi.State, (unsigned long)mbi.Protect, (unsigned long)mbi.Type);
		} else {
			fprintf(stderr, "miniBox: VirtualAlloc(%p, %llu) failed, error %lu\n",
			        (void *)in.start, (unsigned long long)in.size, (unsigned long)err);
		}
		fflush(stderr);
		return -1;
	}
	out->start = (uintptr_t)p;
	out->size = in.size;
	return 0;
}

void mb_pal_unmap_anon(mb_range addr) { VirtualFree((void *)addr.start, 0, MEM_RELEASE); }

int mb_pal_protect(mb_range addr, mb_prot prot) {
	DWORD old;
	return VirtualProtect((void *)addr.start, addr.size, prot_to_native(prot), &old) ? 0 : -1;
}

/* Reserved section pages become real (zero-filled) here; each view of a
 * SEC_RESERVE section is committed on its own, so memblock calls this for the
 * guest view and the mirror separately. */
int mb_pal_commit(mb_range addr, mb_prot prot) {
	if (VirtualAlloc((void *)addr.start, addr.size, MEM_COMMIT, prot_to_native(prot)) != NULL) return 0;
	fprintf(stderr, "miniBox: VirtualAlloc(MEM_COMMIT %p, %llu) failed, error %lu\n",
	        (void *)addr.start, (unsigned long long)addr.size, (unsigned long)GetLastError());
	fflush(stderr);
	return -1;
}

/* Query a region for RWStack dirtiness: the guard bit is cleared once the page
 * has been written (the guard trip auto-clears it). */
int mb_pal_get_stack_dirty(uintptr_t start, uintptr_t *out_size, bool *out_dirty) {
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery((void *)start, &mbi, sizeof(mbi)) != sizeof(mbi)) return -1;
	*out_size = (uintptr_t)mbi.RegionSize;
	*out_dirty = (mbi.Protect & PAGE_GUARD) == 0;
	return 0;
}
#endif
