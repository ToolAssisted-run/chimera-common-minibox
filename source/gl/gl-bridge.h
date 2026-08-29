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

/* Opcodes below 100 are the bridge talking about itself; 100 and up are the
 * generated GL entry points, numbered by the master list (see README.md). */
enum {
	GL_OP_VERSION = 1,    /* args: { char *out; uint32_t size; }        */
	GL_OP_CLEAR_TEST = 2, /* args: { float r,g,b; uint32_t *pixel_out; } */

	/* How many entry points the HOST's master list holds. The list is
	 * append-only, so a host whose list is at least as long as the guest's
	 * knows every opcode the guest can emit - and a guest that learns
	 * otherwise refuses to start rather than calling into a hole. */
	GL_OP_LIST_LENGTH = 3
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
