/* The seam between a sandboxed machine and a real GPU.
 *
 * A waterbox guest has no libraries and no syscalls: it cannot open a display,
 * load libGL, or call anything the host did not hand it. What it CAN do is
 * call one function pointer the host registers with the sandbox
 * (wbx_get_callback_addr), whose shape is fixed - six integers in, one out.
 *
 * So every GL call the renderer makes crosses as (opcode, pointer to an
 * argument block in GUEST memory). The host is inside the same address space,
 * so it reads those arguments - and the vertex data and textures they point at
 * - directly, with no copying. That is what makes this affordable.
 *
 * The traffic is one-way by construction. The guest may hand the host pointers
 * into its own memory; the host may never hand back a pointer into the host's,
 * because the sandbox stops the guest reading it (and rightly). Anything a GL
 * call returns by pointer - a version string, a shader log - is copied into a
 * buffer the guest supplied.
 *
 * WHAT THIS COSTS. The GPU is outside the sandbox, which means it is outside
 * the savestate, outside the determinism the rest of this core is built on,
 * and different on every machine. This is an experiment, off by default, and a
 * core running this way must say so rather than pretend its movies replay.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

/* Opcodes below 100 are the bridge talking about itself; 100 and up are the
 * generated GL entry points, numbered by the master list (see README.md). */
enum {
	GL_OP_VERSION = 1,    /* args: { char *out; uint32_t size; }        */
	GL_OP_CLEAR_TEST = 2, /* args: { float r,g,b; uint32_t *pixel_out; } */

	/* How many entry points the HOST's master list holds. The list is
	 * append-only, so a host whose list is at least as long as the guest's
	 * knows every opcode the guest can emit - and a guest that learns
	 * otherwise refuses to start rather than calling into a hole. */
	GL_OP_LIST_LENGTH = 3,

	/* Which context this is. Every GL object a renderer holds is a NAME the
	 * driver handed out, and those names live in guest memory - so they go
	 * into a savestate, and come back in a session where they mean nothing:
	 * the context that owned them is gone, every call naming one is refused,
	 * and the guest is never told. A renderer that remembers this number
	 * alongside its objects can see that for itself, and rebuild them.
	 *
	 * Any two contexts differ; a host too old to know the question answers 0,
	 * which a guest must read as "cannot tell" rather than as a context. */
	GL_OP_CONTEXT_ID = 4
};

struct GlVersionArgs {
	uint64_t out;    /* guest pointer to a char buffer */
	uint32_t size;
};

struct GlClearTestArgs {
	float r, g, b;
	uint64_t pixel_out; /* guest pointer to one uint32_t */
};

/* The callback's shape, as the sandbox defines it. */
typedef uint64_t (*chimera_gl_bridge_fn)(uint64_t op, uint64_t a, uint64_t b,
                                         uint64_t c, uint64_t d, uint64_t e);

/* The two entry points the generated guest half provides.
 *
 * Declared with C linkage because the half that CALLS them is not always C++:
 * a Rust guest reaches its renderer's loader through the C ABI, and a core
 * written in C would too. The generated file includes this header, so the
 * definitions take this linkage.
 */
#ifdef __cplusplus
extern "C" {
#endif

/* Point the generated wrappers at the host's callback. Returns false when the
 * host's opcode list is shorter than the one this core was built against. */
bool chimera_gl_install(chimera_gl_bridge_fn bridge);

/* What a loader asks for: the wrapper for an entry point, or null when this
 * core does not carry one - which is what a driver answers for a call it does
 * not have. */
void *chimera_gl_lookup(const char *name);

/* Which context the calls are landing on (GL_OP_CONTEXT_ID). Zero when there
 * is no bridge, or the host is older than the question. A renderer that stores
 * this next to its objects can tell, after a savestate load, that the objects
 * it remembers were another context's - and rebuild rather than draw nothing. */
uint64_t chimera_gl_context_id(void);

#ifdef __cplusplus
}
#endif
