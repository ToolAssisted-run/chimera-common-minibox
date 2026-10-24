#!/usr/bin/env python3
"""Generates both sides of the GPU bridge from glad's declarations.

A core reaches OpenGL the way most programs do: through glad, which declares
every entry point as a function POINTER and fills them in at startup. That is
the seam this bridge uses. Nothing in Flycast's renderer is modified - its
pointers are simply made to point at wrappers that hand the call to the host.

For each entry point this writes three things:

  gl-bridge-ops.h        an opcode, and a struct holding that call's arguments,
                         included by both sides so the layout is one definition
  gl-bridge-guest.cpp    the wrapper the guest calls: fill the struct, hand its
                         address to the sandbox's callback
  gl-bridge-host.inc     the host's answer: cast the struct back and make the
                         real call, on the real device

The set of entry points is not "all of OpenGL" - it is what Flycast's GLES
renderer actually names, which is about ninety functions. A name that turns up
later fails loudly at install time rather than silently doing nothing.

Opcodes are indices into the MASTER list (source/gl/gl-entry-points.txt), not
into whatever subset a core happens to use, so every core means the same thing
by the same number and one host can answer them all. See README.md.

Usage: gen-gl-bridge.py <glad gl.h> <master list> <output dir> [--only <subset>]
"""
import os
import re
import sys

# Two calls return a pointer into the DRIVER's memory, which a guest cannot
# read: the sandbox stops it, and should. They are answered by copying the
# string into a buffer on the guest's side and returning that instead.
STRING_RETURNING = {"glGetString", "glGetStringi"}

# Calls whose host side must do NOTHING, because honouring them would hand the
# driver something only the guest may touch. glDebugMessageCallback would give
# it a guest function pointer to call on a host thread, with neither the
# sandbox's ABI shim nor its stack: the wrapper is generated so the renderer
# still links and still "installs" its logger, and the host quietly declines.
HOST_IGNORES = {"glDebugMessageCallback", "glDebugMessageCallbackARB", "glDebugMessageCallbackKHR"}

# A mapped buffer is the driver's memory. A mapping the guest flushes or
# unmaps is given a buffer of the guest's own instead, the size of the range
# (a "shadow"): the host fills it from the driver when the map is made (when
# the guest may read it, or the unmap copies all of it back), copies it to the
# driver on each flush and on the unmap, and the unmap hands it back for the
# guest to free (owner's decision, 2026-10-19). The guest's writes then land in
# its own memory - in its states, and never in the host's. A persistent map
# that is not flushed explicitly (a coherent one, or one only read) keeps the
# driver's pointer: its writes reach the GPU with no call at all, and a copy
# would have to be made before every draw.
#   map: b = the shadow (0: none), c = its size; answers the shadow, or the
#        driver's pointer from a host that does not shadow (the guest then
#        frees its buffer).
#   unmap: b = where the host writes the shadow it gives back (0: none).
SHADOWED_MAPS = {"glMapBufferRange": "range", "glMapNamedBufferRange": "range",
                 "glMapBuffer": "whole", "glMapNamedBuffer": "whole"}
SHADOWED_UNMAPS = {"glUnmapBuffer", "glUnmapNamedBuffer"}


def parse_typedefs(header_text):
    """name -> (return type, [(type, name), ...]) from glad's PFN typedefs."""
    pattern = re.compile(
        r"typedef\s+(.+?)\s*\(GLAD_API_PTR\s*\*\s*PFN(\w+)PROC\)\s*\((.*?)\);",
        re.S)
    out = {}
    for ret, upper, params in pattern.findall(header_text):
        name = "gl" + upper[2:].lower() if False else None  # (see below)
        # glad spells the typedef in upper case: PFNGLDRAWARRAYSPROC. The
        # function's real spelling comes from the declaration list instead.
        out.setdefault(upper.upper(), (ret.strip(), params.strip()))
    return out


def parse_declarations(header_text):
    """The real spelling of each entry point, keyed by its typedef name."""
    pattern = re.compile(r"GLAD_API_CALL PFN(\w+)PROC glad_(\w+);")
    return {upper.upper(): real for upper, real in pattern.findall(header_text)}


def split_params(params):
    """['GLenum mode', 'GLint first'] -> [('GLenum', 'mode'), ...]"""
    if params.strip() in ("", "void"):
        return []
    parts, depth, current = [], 0, ""
    for ch in params:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += ch
    parts.append(current)

    result = []
    for i, part in enumerate(parts):
        part = part.strip()
        # the name is the last identifier; everything before it is the type
        match = re.match(r"^(.*?)(\w+)$", part.replace("[]", " *"))
        if not match or not match.group(1).strip():
            result.append((part, f"arg{i}"))
        else:
            result.append((match.group(1).strip(), match.group(2)))
    return result


def body_fill_args(args):
    return "".join(f"\tchimera_a.{arg} = {arg};\n" for _, arg in args)


def read_names(path):
    """One name per line; blanks and # comments ignored."""
    out = []
    for line in open(path):
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


# The entry points that hand the guest names, and the kind each is (the host
# keeps the same list in chimera's gl_bridge.cpp, noteNames). Their wrappers
# raise the guest's marks (GL_OP_NAME_MARKS in gl-bridge.h): (count, list) for
# the ones that fill a list, None for the ones that return one name.
NAME_MAKERS = {
    "glGenTextures": ("CHIMERA_GL_NAME_TEXTURE", "n", "textures"),
    "glCreateTextures": ("CHIMERA_GL_NAME_TEXTURE", "n", "textures"),
    "glGenBuffers": ("CHIMERA_GL_NAME_BUFFER", "n", "buffers"),
    "glCreateBuffers": ("CHIMERA_GL_NAME_BUFFER", "n", "buffers"),
    "glGenFramebuffers": ("CHIMERA_GL_NAME_FRAMEBUFFER", "n", "framebuffers"),
    "glCreateFramebuffers": ("CHIMERA_GL_NAME_FRAMEBUFFER", "n", "framebuffers"),
    "glGenRenderbuffers": ("CHIMERA_GL_NAME_RENDERBUFFER", "n", "renderbuffers"),
    "glCreateRenderbuffers": ("CHIMERA_GL_NAME_RENDERBUFFER", "n", "renderbuffers"),
    "glGenSamplers": ("CHIMERA_GL_NAME_SAMPLER", "count", "samplers"),
    "glCreateSamplers": ("CHIMERA_GL_NAME_SAMPLER", "n", "samplers"),
    "glGenQueries": ("CHIMERA_GL_NAME_QUERY", "n", "ids"),
    "glCreateQueries": ("CHIMERA_GL_NAME_QUERY", "n", "ids"),
    "glGenVertexArrays": ("CHIMERA_GL_NAME_VERTEX_ARRAY", "n", "arrays"),
    "glCreateVertexArrays": ("CHIMERA_GL_NAME_VERTEX_ARRAY", "n", "arrays"),
    "glGenProgramPipelines": ("CHIMERA_GL_NAME_PIPELINE", "n", "pipelines"),
    "glCreateProgramPipelines": ("CHIMERA_GL_NAME_PIPELINE", "n", "pipelines"),
    "glGenTransformFeedbacks": ("CHIMERA_GL_NAME_TRANSFORM_FEEDBACK", "n", "ids"),
    "glCreateTransformFeedbacks": ("CHIMERA_GL_NAME_TRANSFORM_FEEDBACK", "n", "ids"),
    "glCreateProgram": ("CHIMERA_GL_NAME_PROGRAM", None, None),
    "glCreateShader": ("CHIMERA_GL_NAME_PROGRAM", None, None),
    "glCreateShaderProgramv": ("CHIMERA_GL_NAME_PROGRAM", None, None),
}


def main():
    if len(sys.argv) not in (4, 6):
        sys.exit(__doc__)
    header = open(sys.argv[1]).read()
    master = read_names(sys.argv[2])
    outdir = sys.argv[3]

    # A core generates only what it names, but with the master's numbering.
    wanted = master
    if len(sys.argv) == 6:
        if sys.argv[4] != "--only":
            sys.exit(__doc__)
        subset = set(read_names(sys.argv[5]))
        unknown = sorted(n for n in subset if n not in set(master))
        if unknown:
            sys.exit("not in the master list (add them at its END): "
                     + " ".join(unknown))
        wanted = [n for n in master if n in subset]

    opcode_of = {name: 100 + i for i, name in enumerate(master)}

    typedefs = parse_typedefs(header)
    spellings = parse_declarations(header)
    by_name = {}
    for upper, real in spellings.items():
        if upper in typedefs:
            by_name[real] = typedefs[upper]

    missing = [n for n in wanted if n not in by_name]
    entries = [(n, *by_name[n]) for n in wanted if n in by_name]

    ops, guest, host = [], [], []
    ops.append("/* How many entry points the MASTER list holds. A guest built")
    ops.append(" * against a longer one than the host has refuses to start. */")
    ops.append(f"#define CHIMERA_GL_OP_LIST_LENGTH {len(master)}")
    ops.append("")
    for name, ret, params in entries:
        index = opcode_of[name]
        args = split_params(params)
        struct = f"ChimeraGlArgs_{name}"

        ops.append(f"/* {ret} {name}({params}) */")
        ops.append(f"#define CHIMERA_GL_OP_{name} {index}")
        if args:
            ops.append(f"struct {struct} {{")
            for type_, arg in args:
                ops.append(f"\t{type_} {arg};")
            ops.append("};")
        ops.append("")

        signature = ", ".join(f"{t} {a}" for t, a in args) or "void"
        call_args = ", ".join(f"chimera_p->{a}" for t, a in args)

        if name in HOST_IGNORES:
            body_fill = "".join(f"\tchimera_a.{arg} = {arg};\n" for _, arg in args)
            guest.append(f"""static void GLAD_API_PTR w_{name}({signature})
{{
	struct {struct} chimera_a;
{body_fill}	g_bridge(CHIMERA_GL_OP_{name}, (uint64_t)(uintptr_t)&chimera_a, 0, 0, 0, 0);
}}
""")
            host.append(f"""		case CHIMERA_GL_OP_{name}:
			/* declined: see HOST_IGNORES in the generator */
			(void)a;
			return 0;""")
            continue

        if name in SHADOWED_MAPS:
            named = "Named" in name
            if SHADOWED_MAPS[name] == "range":
                size_expr = "(uint64_t)length"
                shadow_if = "chimera_gl_shadows(access)"
            else:
                # no length: the host answers the buffer's size (GL_OP_BUFFER_SIZE),
                # and a host that does not know the question answers 0 - no shadow
                key = "(uint64_t)buffer, 1" if named else "(uint64_t)target, 0"
                size_expr = f"g_bridge(GL_OP_BUFFER_SIZE, {key}, 0, 0, 0)"
                shadow_if = "true"
            guest.append(f"""static {ret} GLAD_API_PTR w_{name}({signature})
{{
	struct {struct} chimera_a;
{body_fill_args(args)}	const uint64_t chimera_size = {shadow_if} ? {size_expr} : 0;
	void *chimera_shadow = chimera_size != 0 ? chimera_gl_shadow_new(chimera_size) : nullptr;
	const uint64_t chimera_r = g_bridge(CHIMERA_GL_OP_{name}, (uint64_t)(uintptr_t)&chimera_a,
		(uint64_t)(uintptr_t)chimera_shadow, chimera_shadow ? chimera_size : 0, 0, 0);
	if (chimera_shadow != nullptr && chimera_r != (uint64_t)(uintptr_t)chimera_shadow)
		chimera_gl_shadow_free(chimera_shadow);   /* not taken: a host that does not shadow, or a refused map */
	return ({ret})(uintptr_t)chimera_r;
}}
""")
            # a host that does not shadow maps as before: the driver's pointer
            # (Chimera's own case shadows; see SHADOWED_MAPS)
            host.append(f"""		case CHIMERA_GL_OP_{name}:
		{{
			struct {struct} *chimera_p = (struct {struct} *)a;
			if (glad_{name} == NULL) {{ CHIMERA_GL_UNSUPPLIED(CHIMERA_GL_OP_{name}, "{name}"); return 0; }}
			return (uintptr_t){name}({call_args});
		}}""")
            continue

        if name in SHADOWED_UNMAPS:
            guest.append(f"""static {ret} GLAD_API_PTR w_{name}({signature})
{{
	struct {struct} chimera_a;
	uint64_t chimera_shadow = 0;
{body_fill_args(args)}	const {ret} chimera_r = ({ret})g_bridge(CHIMERA_GL_OP_{name}, (uint64_t)(uintptr_t)&chimera_a,
		(uint64_t)(uintptr_t)&chimera_shadow, 0, 0, 0);
	if (chimera_shadow != 0)
		chimera_gl_shadow_free((void *)(uintptr_t)chimera_shadow);
	return chimera_r;
}}
""")
            host.append(f"""		case CHIMERA_GL_OP_{name}:
		{{
			struct {struct} *chimera_p = (struct {struct} *)a;
			if (glad_{name} == NULL) {{ CHIMERA_GL_UNSUPPLIED(CHIMERA_GL_OP_{name}, "{name}"); return 0; }}
			return (uintptr_t){name}({call_args});
		}}""")
            continue

        if name in STRING_RETURNING:
            # the guest supplies the buffer; see STRING_RETURNING above. The
            # answer is then given a place of its own (gl-string-keep.inc): the
            # buffer is one, and a caller holding two answers at once - vendor
            # and version, say - would otherwise hold the second one twice.
            key_index = "(unsigned)index" if any(arg == "index" for _, arg in args) else "CHIMERA_GL_STRING_NO_INDEX"
            guest.append(f"""static const GLubyte *GLAD_API_PTR w_{name}({signature})
{{
	/* 64 KiB: an extension list is longer than 4 KiB on a desktop driver
	 * (NVIDIA's runs to 10 KB and more), and was cut at 4095 bytes - the
	 * extensions past the cut were simply not there (2026-10-18) */
	static char buffer[65536];
	const char *kept;
	struct {struct} chimera_a;
""" + "".join(f"\tchimera_a.{arg} = {arg};\n" for _, arg in args) + f"""	g_bridge(CHIMERA_GL_OP_{name}, (uint64_t)(uintptr_t)&chimera_a,
		(uint64_t)(uintptr_t)buffer, sizeof buffer, 0, 0);
	if (!buffer[0]) return NULL;
	kept = chimera_gl_string_keep((unsigned)name, {key_index}, buffer);
	return (const GLubyte *)(kept ? kept : buffer);
}}
""")
            host.append(f"""		case CHIMERA_GL_OP_{name}:
		{{
			struct {struct} *chimera_p = (struct {struct} *)a;
			const char *s = (const char *){name}({call_args});
			char *out = (char *)b;
			if (out && c) {{ if (s) {{ snprintf(out, (size_t)c, "%s", s); }} else {{ out[0] = 0; }} }}
			return 0;
		}}""")
            continue

        body_fill = "".join(f"\tchimera_a.{arg} = {arg};\n" for _, arg in args)
        if name in NAME_MAKERS:
            kind, count, names = NAME_MAKERS[name]
            arg_names = [arg for _, arg in args]
            if count is not None and (ret != "void" or count not in arg_names or names not in arg_names):
                sys.exit(f"{name}: not the (count, names) shape NAME_MAKERS expects")
            if count is None and ret == "void":
                sys.exit(f"{name}: NAME_MAKERS expects it to return the name")
            call = (f"g_bridge(CHIMERA_GL_OP_{name}, (uint64_t)(uintptr_t)&chimera_a, 0, 0, 0, 0)" if args
                    else f"g_bridge(CHIMERA_GL_OP_{name}, 0, 0, 0, 0, 0)")
            fill = body_fill if args else ""
            decl = f"\tstruct {struct} chimera_a;\n" if args else ""
            if count is not None:
                guest.append(f"""static void GLAD_API_PTR w_{name}({signature})
{{
{decl}{fill}	{call};
	chimera_gl_mark({kind}, {names}, {count});
}}
""")
            else:
                guest.append(f"""static {ret} GLAD_API_PTR w_{name}({signature})
{{
{decl}{fill}	const GLuint chimera_r = (GLuint){call};
	chimera_gl_mark({kind}, &chimera_r, 1);
	return ({ret})chimera_r;
}}
""")
            marked = True
        else:
            marked = False
        if ret == "void":
            if not marked:
                guest.append(f"""static void GLAD_API_PTR w_{name}({signature})
{{
	struct {struct} chimera_a;
{body_fill}	g_bridge(CHIMERA_GL_OP_{name}, (uint64_t)(uintptr_t)&chimera_a, 0, 0, 0, 0);
}}
""" if args else f"""static void GLAD_API_PTR w_{name}(void)
{{
	g_bridge(CHIMERA_GL_OP_{name}, 0, 0, 0, 0, 0);
}}
""")
            host.append(f"""		case CHIMERA_GL_OP_{name}:
		{{
			{f'struct {struct} *chimera_p = (struct {struct} *)a;' if args else '(void)a;'}
			if (glad_{name} == NULL) {{ CHIMERA_GL_UNSUPPLIED(CHIMERA_GL_OP_{name}, "{name}"); return 0; }}
			{name}({call_args});
			return 0;
		}}""")
        else:
            if not marked:
                guest.append(f"""static {ret} GLAD_API_PTR w_{name}({signature})
{{
	struct {struct} chimera_a;
{body_fill}	return ({ret})g_bridge(CHIMERA_GL_OP_{name}, (uint64_t)(uintptr_t)&chimera_a, 0, 0, 0, 0);
}}
""" if args else f"""static {ret} GLAD_API_PTR w_{name}(void)
{{
	return ({ret})g_bridge(CHIMERA_GL_OP_{name}, 0, 0, 0, 0, 0);
}}
""")
            host.append(f"""		case CHIMERA_GL_OP_{name}:
		{{
			{f'struct {struct} *chimera_p = (struct {struct} *)a;' if args else '(void)a;'}
			if (glad_{name} == NULL) {{ CHIMERA_GL_UNSUPPLIED(CHIMERA_GL_OP_{name}, "{name}"); return 0; }}
			return (uintptr_t){name}({call_args});
		}}""")

    banner = ("/* GENERATED by tools/gen-gl-bridge.py from glad's declarations.\n"
              " * Do not edit; edit the generator or the name list beside it. */\n")

    with open(f"{outdir}/gl-bridge-ops.h", "w") as f:
        f.write(banner + "#pragma once\n\n" + "\n".join(ops) + "\n")

    # A core that loads glad itself (PCSX2 does: gladLoadGL over its context's
    # GetProcAddress) needs the wrappers BY NAME rather than assigned. Going
    # through glad's own loader is what makes its GLAD_GL_* version and
    # extension flags come out of the real driver instead of being invented.
    lookup = ["struct ChimeraGlEntry { const char *name; void *fn; };",
              "static const struct ChimeraGlEntry g_entries[] = {"]
    for n, _, _ in entries:
        lookup.append(f'\t{{ "{n}", (void *)w_{n} }},')
    lookup.append("};")
    lookup.append("""
/* What a glad loader asks for. Unknown names answer null, which is what glad
 * expects for an entry point the driver does not have. */
void *chimera_gl_lookup(const char *name)
{
	for (size_t i = 0; i < sizeof g_entries / sizeof *g_entries; i++)
	{
		if (std::strcmp(g_entries[i].name, name) == 0)
			return g_entries[i].fn;
	}

	return nullptr;
}""")

    # pasted in rather than included: a core's build finds this generator by
    # path, and not every core has this directory on its include path
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "gl-string-keep.inc")) as f:
        string_keep = f.read()

    with open(f"{outdir}/gl-bridge-guest.cpp", "w") as f:
        f.write(banner + f"""
/* The guest's side: {len(entries)} entry points, each one a struct and a call
 * to the sandbox's single callback. Installing them is the whole of what makes
 * this core's renderer talk to a GPU it cannot see. */
#include <glad/gl.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "gl-bridge.h"
#include "gl-bridge-ops.h"

static chimera_gl_bridge_fn g_bridge;

/* The shadows of mapped buffers (SHADOWED_MAPS in the generator): memory of
 * the guest's own, aligned as a driver's mapping is. */
static bool chimera_gl_shadows(GLbitfield access)
{{
	if ((access & GL_MAP_PERSISTENT_BIT) == 0) return true;   /* unmapped before it is used */
	/* persistent: shadowed only when its writes are flushed explicitly */
	return (access & GL_MAP_COHERENT_BIT) == 0 && (access & GL_MAP_FLUSH_EXPLICIT_BIT) != 0 && (access & GL_MAP_WRITE_BIT) != 0;
}}
/* A shadow's size is kept in the 64 bytes before it. One freed shadow is kept
 * for the next map of a like size: a renderer that maps and unmaps every frame
 * would otherwise be given new memory each time, and fault in every page of
 * it. It is the guest's memory, so a state holds it like any other. */
static void *chimera_gl_spare;
static uint64_t chimera_gl_shadow_size(void *p)
{{
	return *(uint64_t *)((char *)p - 64);
}}
static void *chimera_gl_shadow_new(uint64_t size)
{{
	const uint64_t need = (size + 63) & ~(uint64_t)63;
	if (chimera_gl_spare != nullptr)
	{{
		const uint64_t has = chimera_gl_shadow_size(chimera_gl_spare);
		if (has >= need && has / 2 <= need)
		{{
			void *p = chimera_gl_spare;
			chimera_gl_spare = nullptr;
			return p;
		}}
	}}
	void *base = nullptr;
	if (posix_memalign(&base, 64, (size_t)(need + 64)) != 0) return nullptr;
	*(uint64_t *)base = need;
	return (char *)base + 64;
}}
/* The highest name of each kind the driver has handed this guest
 * (GL_OP_NAME_MARKS): guest memory, so every state holds it, and the host
 * reads it after a load to keep those numbers from new objects. */
static struct ChimeraGlNameMarks g_name_marks = {{ CHIMERA_GL_NAME_MARKS_MAGIC, CHIMERA_GL_NAME_KINDS, {{ 0 }} }};
static void chimera_gl_mark(unsigned kind, const GLuint *names, GLsizei n)
{{
	if (names == nullptr || kind >= CHIMERA_GL_NAME_KINDS) return;
	for (GLsizei i = 0; i < n; i++)
		if (names[i] > g_name_marks.high[kind]) g_name_marks.high[kind] = names[i];
}}

static void chimera_gl_shadow_free(void *p)
{{
	if (p == nullptr) return;
	if (chimera_gl_spare == nullptr)
	{{
		chimera_gl_spare = p;
		return;
	}}
	void *drop = p;
	if (chimera_gl_shadow_size(p) > chimera_gl_shadow_size(chimera_gl_spare))
	{{
		drop = chimera_gl_spare;   /* the larger one is kept */
		chimera_gl_spare = p;
	}}
	std::free((char *)drop - 64);
}}

""" + string_keep + "\n" + "\n".join(guest) + f"""
/* Returns false when the host is older than this guest - it would not know
 * every opcode this guest can emit, and the core must draw some other way. */
bool chimera_gl_install(chimera_gl_bridge_fn bridge)
{{
	uint64_t host_length = bridge(GL_OP_LIST_LENGTH, 0, 0, 0, 0, 0);
	if (host_length < CHIMERA_GL_OP_LIST_LENGTH)
	{{
		fprintf(stderr, "chimera gl: the host knows %llu entry points and this "
			"core was built against %d; not bridging\\n",
			(unsigned long long)host_length, CHIMERA_GL_OP_LIST_LENGTH);
		return false;
	}}

	g_bridge = bridge;
	/* where the marks are; a host that does not ask about them says it has no
	 * case for the opcode, once, and nothing changes */
	bridge(GL_OP_NAME_MARKS, (uint64_t)(uintptr_t)&g_name_marks, sizeof g_name_marks, 0, 0, 0);
""" + "".join(f"\tglad_{n} = w_{n};\n" for n, _, _ in entries) + """	return true;
}

/* Which context the calls land on. Zero means "cannot tell": no bridge, or a
 * host that predates the question - and a renderer must treat that as "assume
 * nothing changed" rather than as a context of its own. */
uint64_t chimera_gl_context_id(void)
{
	return g_bridge ? g_bridge(GL_OP_CONTEXT_ID, 0, 0, 0, 0, 0) : 0;
}

"""
                + "\n".join(lookup) + "\n")

    # A function the driver did not supply is a null glad pointer, and the guest
    # has a wrapper for every name: the case answers 0, as a call the driver
    # refused, instead of calling through null and ending the process
    # (2026-10-18). A host that wants it said defines CHIMERA_GL_UNSUPPLIED
    # before including this; the core repos' test runners need not.
    unsupplied = ("#ifndef CHIMERA_GL_UNSUPPLIED\n"
                  "#define CHIMERA_GL_UNSUPPLIED(op, name) ((void)0)\n"
                  "#endif\n")
    # The guest says where its name marks are (GL_OP_NAME_MARKS) as it
    # installs. A host that never gives a guest a fresh context - a core
    # repository's test runner - has no use for them and answers nothing; one
    # that does (Chimera's) defines CHIMERA_GL_HOST_NAME_MARKS and answers it
    # itself. Without this case such a runner says it has no case for the
    # opcode, which its gate counts as a fault.
    marks_case = ("#ifndef CHIMERA_GL_HOST_NAME_MARKS\n"
                  "\t\tcase GL_OP_NAME_MARKS:\n"
                  "\t\t\t(void)a;\n"
                  "\t\t\treturn 0;\n"
                  "#endif\n")
    with open(f"{outdir}/gl-bridge-host.inc", "w") as f:
        f.write(banner + unsupplied + marks_case + "\n".join(host) + "\n")

    print(f"{len(entries)} entry points generated"
          + (f"; {len(missing)} not found in glad: {' '.join(missing)}" if missing else ""))


if __name__ == "__main__":
    main()
