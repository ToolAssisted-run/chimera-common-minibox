#define _GNU_SOURCE
/* Minimal ELF64 loader for guest images. The guest is a static, non-PIE
 * ET_EXEC linked at a fixed base - there are NO relocations to process, so this
 * only reads program headers (to load segments), the symbol table (for exports
 * and __wbxsysinfo), and section headers (for invisible/RO-after-seal handling).
 * Faithful C port of BizHawk waterboxhost src/elf.rs; replaces the goblin crate. */
#include "minibox_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---- ELF64 structures (subset) ---- */
typedef struct {
	uint8_t  e_ident[16];
	uint16_t e_type, e_machine;
	uint32_t e_version;
	uint64_t e_entry, e_phoff, e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr;
typedef struct {
	uint32_t p_type, p_flags;
	uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} Elf64_Phdr;
typedef struct {
	uint32_t sh_name, sh_type;
	uint64_t sh_flags, sh_addr, sh_offset, sh_size;
	uint32_t sh_link, sh_info;
	uint64_t sh_addralign, sh_entsize;
} Elf64_Shdr;
typedef struct {
	uint32_t st_name;
	uint8_t  st_info, st_other;
	uint16_t st_shndx;
	uint64_t st_value, st_size;
} Elf64_Sym;

#define PT_LOAD 1
#define PT_TLS  7
#define PF_X 1
#define PF_W 2
#define PF_R 4
#define SHT_NOBITS 8
#define STB_GLOBAL 1
#define STV_DEFAULT 0

typedef struct { char *name; mb_range addr; } section_info;
typedef struct { char *name; uintptr_t value, size; } export_info;

struct mb_elf {
	section_info *sections; size_t nsections;
	export_info  *exports;  size_t nexports;
	uintptr_t entry;
	uint8_t hash[32];
	/* Does this guest carry ELF thread-local storage (PT_TLS)? Only a guest
	 * built by a toolchain that emits %fs-relative TLS does - Rust does, and
	 * every C/C++ guest built against the waterbox musl does NOT, because that
	 * musl reaches its thread pointer through %gs instead. It decides whether
	 * the host swaps %fs around guest execution at all. */
	bool has_tls;
};

static bool section_ro_after_seal(const char *n) {
	return strstr(n, ".rel.ro") || strncmp(n, ".got", 4) == 0
		|| strcmp(n, ".init_array") == 0 || strcmp(n, ".fini_array") == 0
		|| strcmp(n, ".tbss") == 0 || strcmp(n, ".sealed") == 0;
}

mb_range mb_elf_span(const uint8_t *image, size_t len) {
	const Elf64_Ehdr *eh = (const Elf64_Ehdr *)image;
	uintptr_t lo = (uintptr_t)-1, hi = 0;
	for (int i = 0; i < eh->e_phnum; i++) {
		const Elf64_Phdr *ph = (const Elf64_Phdr *)(image + eh->e_phoff + (size_t)i * eh->e_phentsize);
		if (ph->p_vaddr == 0) continue;
		(void)len;
		if (ph->p_vaddr < lo) lo = ph->p_vaddr;
		if (ph->p_vaddr + ph->p_memsz > hi) hi = ph->p_vaddr + ph->p_memsz;
	}
	mb_range r = { lo, hi - lo };
	return r;
}

int mb_elf_load(const uint8_t *image, size_t image_len, const char *module_name,
                const mb_layout *layout, mb_block *b, mb_elf **out) {
	const Elf64_Ehdr *eh = (const Elf64_Ehdr *)image;
	if (image_len < sizeof(Elf64_Ehdr) || memcmp(eh->e_ident, "\x7f""ELF", 4) != 0 || eh->e_ident[4] != 2) {
		fprintf(stderr, "miniBox: not an ELF64 image\n");
		return -1;
	}
	mb_elf *e = (mb_elf *)calloc(1, sizeof(mb_elf));
	e->entry = eh->e_entry;

	/* section headers + shstrtab */
	const Elf64_Shdr *sh = (const Elf64_Shdr *)(image + eh->e_shoff);
	const Elf64_Shdr *shstr = &sh[eh->e_shstrndx];
	const char *shstrtab = (const char *)(image + shstr->sh_offset);
	e->sections = (section_info *)calloc(eh->e_shnum, sizeof(section_info));
	const Elf64_Shdr *symtab = NULL, *strtab_sh = NULL;
	for (int i = 0; i < eh->e_shnum; i++) {
		const char *name = shstrtab + sh[i].sh_name;
		if (sh[i].sh_type != SHT_NOBITS && name[0] && sh[i].sh_addr != 0) {
			e->sections[e->nsections].name = strdup(name);
			e->sections[e->nsections].addr.start = sh[i].sh_addr;
			e->sections[e->nsections].addr.size = sh[i].sh_size;
			e->nsections++;
		}
		if (sh[i].sh_type == 2 /*SHT_SYMTAB*/) { symtab = &sh[i]; strtab_sh = &sh[sh[i].sh_link]; }
	}

	/* exports + __wbxsysinfo */
	mb_range info_area = { 0, 0 };
	if (symtab && strtab_sh) {
		size_t nsym = symtab->sh_size / sizeof(Elf64_Sym);
		const Elf64_Sym *syms = (const Elf64_Sym *)(image + symtab->sh_offset);
		const char *strtab = (const char *)(image + strtab_sh->sh_offset);
		e->exports = (export_info *)calloc(nsym, sizeof(export_info));
		for (size_t i = 0; i < nsym; i++) {
			const char *name = strtab + syms[i].st_name;
			if (!name[0]) continue;
			uint8_t bind = syms[i].st_info >> 4;
			uint8_t vis = syms[i].st_other & 3;
			if (vis == STV_DEFAULT && bind == STB_GLOBAL) {
				e->exports[e->nexports].name = strdup(name);
				e->exports[e->nexports].value = syms[i].st_value;
				e->exports[e->nexports].size = syms[i].st_size;
				e->nexports++;
			}
			if (strcmp(name, "__wbxsysinfo") == 0) { info_area.start = syms[i].st_value; info_area.size = syms[i].st_size; }
		}
	}

	/* mark .invis invisible (with overlap validation), then the invis arena */
	for (size_t i = 0; i < e->nsections; i++) {
		if (strcmp(e->sections[i].name, ".invis") == 0) {
			mb_range iv = mb_range_align_expand(e->sections[i].addr);
			for (size_t j = 0; j < e->nsections; j++) {
				if (j == i) continue;
				mb_range s = mb_range_align_expand(e->sections[j].addr);
				if (s.size == 0) continue;
				bool overlap = s.start < mb_range_end(iv) && iv.start < mb_range_end(s);
				if (overlap) { fprintf(stderr, "miniBox: section %s overlaps .invis - check linkscript\n", e->sections[j].name); goto fail; }
			}
			mb_block_mark_invisible(b, iv);
			break;
		}
	}
	mb_block_mark_invisible(b, layout->invis);

	/* load PT_LOAD segments (and note PT_TLS on the way past: see has_tls) */
	for (int i = 0; i < eh->e_phnum; i++) {
		const Elf64_Phdr *ph = (const Elf64_Phdr *)(image + eh->e_phoff + (size_t)i * eh->e_phentsize);
		if (ph->p_type == PT_TLS && ph->p_memsz != 0) e->has_tls = true;
		if (ph->p_type != PT_LOAD || ph->p_vaddr == 0) continue;
		mb_range addr = { ph->p_vaddr, ph->p_memsz };
		mb_range pa = mb_range_align_expand(addr);
		if (pa.size == 0) continue;
		mb_prot prot;
		bool r = ph->p_flags & PF_R, w = ph->p_flags & PF_W, x = ph->p_flags & PF_X;
		if (w) prot = x ? MB_PROT_RWX : MB_PROT_RW;
		else if (x) prot = MB_PROT_RX;
		else if (r) prot = MB_PROT_R;
		else prot = MB_PROT_NONE;
		mb_block_mmap_fixed(b, pa, MB_PROT_RW, false);
		if (ph->p_filesz) mb_block_copy_from_external(b, image + ph->p_offset, ph->p_vaddr, ph->p_filesz);
		mb_block_mprotect(b, pa, prot);
	}

	/* fill __wbxsysinfo */
	if (info_area.start) {
		if (info_area.size != sizeof(mb_layout)) { fprintf(stderr, "miniBox: __wbxsysinfo wrong size\n"); goto fail; }
		mb_block_copy_from_external(b, (const uint8_t *)layout, info_area.start, sizeof(mb_layout));
	}

	/* guest stacks: RWStack, guard the low 4 pages, invisible */
	mb_block_mmap_fixed(b, layout->main_thread, MB_PROT_RWSTACK, true);
	{ mb_range g = { layout->main_thread.start, MB_PAGESIZE * 4 }; mb_block_mprotect(b, g, MB_PROT_NONE); }
	mb_block_mark_invisible(b, layout->main_thread);
	mb_block_mmap_fixed(b, layout->alt_thread, MB_PROT_RWSTACK, true);
	{ mb_range g = { layout->alt_thread.start, MB_PAGESIZE * 4 }; mb_block_mprotect(b, g, MB_PROT_NONE); }
	mb_block_mark_invisible(b, layout->alt_thread);

	{ mb_sha256 s; mb_sha256_init(&s); mb_sha256_update(&s, image, image_len); mb_sha256_final(&s, e->hash); }

	(void)module_name;
	*out = e;
	return 0;
fail:
	mb_elf_free(e);
	return -1;
}

void mb_elf_free(mb_elf *e) {
	if (!e) return;
	for (size_t i = 0; i < e->nsections; i++) free(e->sections[i].name);
	for (size_t i = 0; i < e->nexports; i++) free(e->exports[i].name);
	free(e->sections); free(e->exports); free(e);
}

uintptr_t mb_elf_entry(const mb_elf *e) { return e->entry; }
bool mb_elf_has_tls(const mb_elf *e) { return e->has_tls; }

uintptr_t mb_elf_proc_addr(const mb_elf *e, const char *name) {
	for (size_t i = 0; i < e->nexports; i++)
		if (strcmp(e->exports[i].name, name) == 0) return e->exports[i].value;
	return 0;
}

void mb_elf_seal(mb_elf *e, mb_block *b) {
	for (size_t i = 0; i < e->nsections; i++) {
		mb_range pa = mb_range_align_expand(e->sections[i].addr);
		if (pa.size != 0 && section_ro_after_seal(e->sections[i].name))
			mb_block_mprotect(b, pa, MB_PROT_R);
	}
}

const uint8_t *mb_elf_hash(const mb_elf *e) { return e->hash; }
