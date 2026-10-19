/* Platform abstraction layer, Windows x86-64. Mirrors BizHawk waterboxhost src/memory_block/
 * pal.rs (the win module). CROSS-COMPILE-CHECKED with mingw-w64; not
 * runtime-validated on Linux. */
#ifdef _WIN32
#include "minibox_internal.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/* ---- a lazy block made of pieces ----------------------------------------
 *
 * A page of a view of a section cannot be given back: VirtualFree refuses to
 * decommit it (error 87, measured 2026-10-18), and MEM_RESET keeps the bytes.
 * So memory a core freed stayed taken until the core was closed - the PS3
 * core's block is 20 GiB of address space. A lazy block (over 4 GiB) is
 * therefore made of pieces, a section each, and each of its views (the
 * guest's, and the mirror) is built of those sections on reserved address
 * space (placeholders, Windows 10 1803 and later): a piece whose pages the
 * core has all given back is unmapped from every view and its section closed,
 * which gives its memory back, and is made again, empty, when the core maps
 * there next. Where Windows has no placeholders the block is one section, as
 * before. MB_NO_PIECES set in the environment asks for that too. */
#define MB_PAL_PIECE ((uintptr_t)16 << 20)

typedef PVOID (WINAPI *va2_fn)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER *, ULONG);
typedef PVOID (WINAPI *mv3_fn)(HANDLE, HANDLE, PVOID, ULONG64, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER *, ULONG);
typedef BOOL (WINAPI *uv2_fn)(HANDLE, PVOID, ULONG);
static va2_fn s_va2;
static mv3_fn s_mv3;
static uv2_fn s_uv2;
static int s_placeholders = -1;

static bool placeholders(void) {
	if (s_placeholders < 0) {
		HMODULE k = GetModuleHandleA("kernelbase.dll");
		if (k) {
			s_va2 = (va2_fn)(void *)GetProcAddress(k, "VirtualAlloc2");
			s_mv3 = (mv3_fn)(void *)GetProcAddress(k, "MapViewOfFile3");
			s_uv2 = (uv2_fn)(void *)GetProcAddress(k, "UnmapViewOfFile2");
		}
		char v[4];
		const bool refused = GetEnvironmentVariableA("MB_NO_PIECES", v, sizeof v) > 0;
		s_placeholders = s_va2 && s_mv3 && s_uv2 && !refused;
	}
	return s_placeholders == 1;
}

typedef struct {
	uintptr_t size;
	size_t n;
	HANDLE *sections;      /* a piece's section; NULL: never backed, or given back */
	uintptr_t views[2];    /* where each view of the block starts */
	int nviews;
} mb_pieces;

static mb_pieces *pieces_of(mb_handle h) { return (mb_pieces *)h.h; }
static uintptr_t piece_size(const mb_pieces *p, size_t i) {
	return i + 1 < p->n ? MB_PAL_PIECE : p->size - (p->n - 1) * MB_PAL_PIECE;
}

/* map piece i's section into view v, in place of its placeholder */
static bool map_piece(mb_pieces *p, int v, size_t i) {
	PVOID at = (PVOID)(p->views[v] + i * MB_PAL_PIECE);
	return s_mv3(p->sections[i], GetCurrentProcess(), at, 0, piece_size(p, i),
	             MEM_REPLACE_PLACEHOLDER, PAGE_EXECUTE_READWRITE, NULL, 0) == at;
}

/* back piece i with a new, empty section, in every view */
static bool make_piece(mb_pieces *p, size_t i) {
	const uintptr_t sz = piece_size(p, i);
	HANDLE s = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE | SEC_RESERVE,
	                              (DWORD)((uint64_t)sz >> 32), (DWORD)sz, NULL);
	if (s == NULL) return false;
	p->sections[i] = s;
	for (int v = 0; v < p->nviews; v++) {
		if (map_piece(p, v, i)) continue;
		fprintf(stderr, "miniBox: a piece of a block could not be mapped (error %lu)\n", (unsigned long)GetLastError());
		fflush(stderr);
		for (int u = 0; u < v; u++) s_uv2(GetCurrentProcess(), (PVOID)(p->views[u] + i * MB_PAL_PIECE), MEM_PRESERVE_PLACEHOLDER);
		CloseHandle(s);
		p->sections[i] = NULL;
		return false;
	}
	return true;
}

static int view_of(const mb_pieces *p, uintptr_t addr) {
	for (int v = 0; v < p->nviews; v++)
		if (addr >= p->views[v] && addr - p->views[v] < p->size) return v;
	return -1;
}

static uint32_t prot_to_native(mb_prot prot) {
	switch (prot) {
		case MB_PROT_NONE:    return PAGE_NOACCESS;
		case MB_PROT_R:       return PAGE_READONLY;
		case MB_PROT_RW:      return PAGE_READWRITE;
		case MB_PROT_RX:      return PAGE_EXECUTE_READ;
		case MB_PROT_RWX:     return PAGE_EXECUTE_READWRITE;
		case MB_PROT_RWSTACK: return PAGE_READWRITE;
	}
	return PAGE_NOACCESS;
}

int mb_pal_open_handle(uintptr_t size, mb_handle *out) {
	out->pieces = false;
	if (size > ((uintptr_t)4 << 30) && placeholders()) {
		mb_pieces *p = (mb_pieces *)calloc(1, sizeof *p);
		if (!p) return -1;
		p->size = size;
		p->n = (size + MB_PAL_PIECE - 1) / MB_PAL_PIECE;
		p->sections = (HANDLE *)calloc(p->n, sizeof(HANDLE));
		if (!p->sections) { free(p); return -1; }
		out->h = (uintptr_t)p;
		out->lazy = true;
		out->pieces = true;
		return 0;
	}
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

void mb_pal_close_handle(mb_handle h) {
	if (h.pieces) {
		mb_pieces *p = pieces_of(h);
		for (size_t i = 0; i < p->n; i++)
			if (p->sections[i]) CloseHandle(p->sections[i]);
		free(p->sections);
		free(p);
		return;
	}
	CloseHandle((HANDLE)h.h);
}

int mb_pal_map_handle(mb_handle h, mb_range in, mb_range *out) {
	if (h.pieces) {
		mb_pieces *p = pieces_of(h);
		if (p->nviews == 2 || in.size != p->size) return -1;
		uint8_t *base = (uint8_t *)s_va2(GetCurrentProcess(), (PVOID)in.start, p->size,
		                                 MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, NULL, 0);
		if (base == NULL) return -1;
		/* one placeholder a piece: split off each but the last */
		for (size_t i = 0; i + 1 < p->n; i++) {
			if (!VirtualFree(base + i * MB_PAL_PIECE, MB_PAL_PIECE, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) {
				fprintf(stderr, "miniBox: a block's address space could not be split into pieces (error %lu)\n",
				        (unsigned long)GetLastError());
				fflush(stderr);
				for (size_t k = 0; k <= i; k++) VirtualFree(base + k * MB_PAL_PIECE, 0, MEM_RELEASE);
				VirtualFree(base + (i + 1) * MB_PAL_PIECE, 0, MEM_RELEASE);
				return -1;
			}
		}
		const int v = p->nviews++;
		p->views[v] = (uintptr_t)base;
		for (size_t i = 0; i < p->n; i++) {
			if (p->sections[i] && !map_piece(p, v, i)) {
				fprintf(stderr, "miniBox: a piece of a block could not be mapped (error %lu)\n", (unsigned long)GetLastError());
				fflush(stderr);
			}
		}
		out->start = (uintptr_t)base;
		out->size = p->size;
		return 0;
	}
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

void mb_pal_unmap_handle(mb_handle h, mb_range addr) {
	if (h.pieces) {
		mb_pieces *p = pieces_of(h);
		const int v = view_of(p, addr.start);
		if (v < 0) return;
		for (size_t i = 0; i < p->n; i++) {
			PVOID at = (PVOID)(p->views[v] + i * MB_PAL_PIECE);
			if (p->sections[i]) UnmapViewOfFile(at);
			else VirtualFree(at, 0, MEM_RELEASE);
		}
		p->views[v] = p->views[--p->nviews];
		return;
	}
	UnmapViewOfFile((void *)addr.start);
}

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

/* Tests only: this many commits are refused as an exhausted system would
 * refuse them (ERROR_COMMITMENT_LIMIT), without having to exhaust one. */
int mb_pal_commit_refusals = 0;

/* Reserved section pages become real (zero-filled) here; each view of a
 * SEC_RESERVE section is committed on its own, so memblock calls this for the
 * guest view and the mirror separately. */
/* Tests only, from outside the library: MB_REFUSE_COMMITS=1 refuses every
 * commit while it is set (run_guest sets and clears it around one call). */
static bool refuse_by_environment(void) {
	char v[4];
	const DWORD n = GetEnvironmentVariableA("MB_REFUSE_COMMITS", v, sizeof v);
	return n > 0 && n < sizeof v && v[0] == '1';
}

int mb_pal_commit(mb_handle h, mb_range addr, mb_prot prot) {
	if (h.pieces && !(mb_pal_commit_refusals > 0 || refuse_by_environment())) {
		/* each piece the range touches has a section, in every view */
		mb_pieces *p = pieces_of(h);
		const int v = view_of(p, addr.start);
		if (v < 0) return -1;
		const size_t first = (addr.start - p->views[v]) / MB_PAL_PIECE;
		const size_t last = (addr.start + addr.size - 1 - p->views[v]) / MB_PAL_PIECE;
		for (size_t i = first; i <= last && i < p->n; i++)
			if (!p->sections[i] && !make_piece(p, i)) {
				SetLastError(ERROR_COMMITMENT_LIMIT);
				goto refused;
			}
		/* and a piece at a time: each is a view of its own, and one commit
		 * cannot cross from one view into the next (error 487, measured on
		 * the PS3 core's first allocation) */
		for (size_t i = first; i <= last && i < p->n; i++) {
			const uintptr_t lo = p->views[v] + i * MB_PAL_PIECE, hi = lo + piece_size(p, i);
			const uintptr_t from = addr.start > lo ? addr.start : lo;
			const uintptr_t to = addr.start + addr.size < hi ? addr.start + addr.size : hi;
			if (VirtualAlloc((void *)from, to - from, MEM_COMMIT, prot_to_native(prot)) == NULL) goto refused;
		}
		return 0;
	}
	if (mb_pal_commit_refusals > 0 || refuse_by_environment()) {
		if (mb_pal_commit_refusals > 0) mb_pal_commit_refusals--;
		SetLastError(ERROR_COMMITMENT_LIMIT);
	} else if (VirtualAlloc((void *)addr.start, addr.size, MEM_COMMIT, prot_to_native(prot)) != NULL) {
		return 0;
	}
refused:
	fprintf(stderr, "miniBox: VirtualAlloc(MEM_COMMIT %p, %llu) failed, error %lu\n",
	        (void *)addr.start, (unsigned long long)addr.size, (unsigned long)GetLastError());
	fflush(stderr);
	return -1;
}

/* Measured 2026-10-18: VirtualFree(MEM_DECOMMIT) on a view of a SEC_RESERVE
 * section fails with error 87; MEM_RESET keeps the bytes; DiscardVirtualMemory
 * frees them, but what reads back is undefined, which a machine cannot use. */
int mb_pal_release(mb_handle h, uintptr_t offset, uintptr_t len) {
	if (!h.pieces) return -1;
	mb_pieces *p = pieces_of(h);
	if (offset % MB_PAL_PIECE || len == 0 || offset >= p->size || len > p->size - offset) return -1;
	if ((offset + len) % MB_PAL_PIECE && offset + len != p->size) return -1;
	for (size_t i = offset / MB_PAL_PIECE; i < p->n && i * MB_PAL_PIECE < offset + len; i++) {
		if (!p->sections[i]) continue;
		for (int v = 0; v < p->nviews; v++)
			s_uv2(GetCurrentProcess(), (PVOID)(p->views[v] + i * MB_PAL_PIECE), MEM_PRESERVE_PLACEHOLDER);
		CloseHandle(p->sections[i]);
		p->sections[i] = NULL;
		/* MB_TRACE_PIECES: say each piece given back (a diagnostic) */
		char v[4];
		if (GetEnvironmentVariableA("MB_TRACE_PIECES", v, sizeof v) > 0) {
			fprintf(stderr, "miniBox: piece %llu of a block given back to Windows\n", (unsigned long long)i);
			fflush(stderr);
		}
	}
	return 0;
}

uintptr_t mb_pal_release_unit(mb_handle h) { return h.pieces ? MB_PAL_PIECE : 0; }

int mb_pal_map_code(uintptr_t size, mb_range *exec, mb_range *write) {
	mb_range in = { 0, size };
	if (mb_pal_map_anon(in, MB_PROT_RWX, exec) != 0) return -1;
	*write = *exec;
	return 0;
}

void mb_pal_unmap_code(mb_range exec, mb_range write) { (void)write; mb_pal_unmap_anon(exec); }

#endif
