#include "emulibc.h"
#include <stdio.h>
#include <sys/mman.h>

// Keep this in sync with the rust code!!
struct __AddressRange {
	unsigned long start;
	unsigned long size;
};
struct __WbxSysLayout {
	struct __AddressRange elf;
	struct __AddressRange main_thread;
	struct __AddressRange alt_thread;
	struct __AddressRange sbrk;
	struct __AddressRange sealed;
	struct __AddressRange invis;
	struct __AddressRange plain;
	struct __AddressRange mmap;
};
ECL_INVISIBLE ECL_EXPORT struct __WbxSysLayout __wbxsysinfo;

/* The guest kit's revision (MACHINE-SPEC, "Guest kit revisions"). An answer
 * the host corrected after cores had shipped goes only to a core that says it
 * was built with a kit that knows it; a core built before has no such symbol
 * and is answered as it always was, so its movies replay. Every core links
 * this file, so a core rebuilt with this kit declares it without doing
 * anything. (Built with WBX_KIT_REVISION=0 only by miniBox's own test of the
 * old answer.) */
#ifndef WBX_KIT_REVISION
#define WBX_KIT_REVISION 2
#endif
#if WBX_KIT_REVISION > 0
ECL_EXPORT const unsigned int __wbx_kit_revision = WBX_KIT_REVISION;
#endif

void* alloc_helper(size_t size, const struct __AddressRange* range, unsigned long* current, const char* name)
{
	if (!*current)
	{
		printf("Initializing heap %s at %p:%p\n", name, (void*)range->start, (void*)(range->start + range->size));
		*current = range->start;
	}

	unsigned long start = *current;
	unsigned long end = start + size;
	end = (end + 15) & ~15ul;

	if (end < start || end > range->start + range->size)
	{
		fprintf(stderr, "Failed to satisfy allocation of %lu bytes on %s heap\n", size, name);
		return NULL;
	}
	else
	{
		unsigned long pstart = (start + 0xfff) & ~0xffful;
		unsigned long pend = (end + 0xfff) & ~0xffful;
		if (pstart < pend)
		{
			if (mmap((void*)pstart, pend - pstart, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_FIXED_NOREPLACE, -1, 0) == MAP_FAILED)
			{
				fprintf(stderr, "VERY STRANGE: mmap() failed to satisfy allocation of %lu bytes on %s heap\n", size, name);
				return NULL;
			}
		}
		printf("Allocated %lu bytes on %s heap, usage %lu/%lu\n", size, name, end - range->start, range->size);
		*current = end;
		return (void*)start;
	}
}

static unsigned long __sealed_current;
void* alloc_sealed(size_t size)
{
	return alloc_helper(size, &__wbxsysinfo.sealed, &__sealed_current, "sealed");
}

static unsigned long __invisible_current;
void* alloc_invisible(size_t size)
{
	return alloc_helper(size, &__wbxsysinfo.invis, &__invisible_current, "invisible");
}

static unsigned long __plain_current;
void* alloc_plain(size_t size)
{
	return alloc_helper(size, &__wbxsysinfo.plain, &__plain_current, "plain");
}

// TODO: This existed before we even had stdio support.  Retire?
void _debug_puts(const char *s)
{
	fprintf(stderr, "%s\n", s);
}

ECL_EXPORT void ecl_seal()
{
	if (__sealed_current)
	{
		if (mprotect((void*)__wbxsysinfo.sealed.start, (__sealed_current - __wbxsysinfo.sealed.start + 0xfff) & ~0xffful, PROT_READ) != 0)
#if defined(__aarch64__)
			__builtin_trap();
#elif defined(__x86_64__)
			__asm__("int3");
#else
#error "miniBox runs on x86-64 and aarch64 only"
#endif
	}
}
