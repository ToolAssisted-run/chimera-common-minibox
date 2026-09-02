/* The compile-cache bridge: a host-kept store of files a core regenerates
 * deterministically from its inputs (an emulator's recompiled modules), named
 * by the core and never part of the machine's state.
 *
 * A core that keeps such files exports SetCacheBridge(uint64_t) and receives
 * the host's dispatcher before Init, through the sandbox's single callback
 * (six integers in, one out, guest ABI). Every call crosses as (op, pointer
 * to an argument block in GUEST memory). The host reads names and data in
 * place and copies fetched bytes into the buffer the guest supplied; it never
 * hands back a host pointer.
 *
 * Names are relative paths ('/' separated) under a directory the host owns
 * for this core and this package: a name with an absolute prefix or a '..'
 * segment is refused. What the host stores is what it was given; a fetch of a
 * name it never stored answers 0.
 *
 * Determinism: a fetched file must be byte-identical to what the core would
 * have generated itself, which is the core's promise (the same package, the
 * same inputs). The host's only job is to keep bytes. */
#pragma once
#include <stdint.h>

enum {
	CACHE_OP_FETCH = 1, /* args: CacheFetchArgs; returns the file's size, 0 if absent.
	                       With cap == 0 only the size is answered; with cap >= size
	                       the bytes are copied to dst. */
	CACHE_OP_STORE = 2, /* args: CacheStoreArgs; returns 1 when kept, 0 when refused */
};

struct CacheFetchArgs {
	uint64_t name;     /* guest pointer to the name (not terminated) */
	uint64_t name_len;
	uint64_t dst;      /* guest pointer, or 0 */
	uint64_t cap;      /* bytes available at dst */
};

struct CacheStoreArgs {
	uint64_t name;
	uint64_t name_len;
	uint64_t data;     /* guest pointer */
	uint64_t size;
};

typedef uint64_t (*chimera_cache_bridge_fn)(uint64_t op, uint64_t a, uint64_t b,
                                            uint64_t c, uint64_t d, uint64_t e);
