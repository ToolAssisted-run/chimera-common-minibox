# The GPU bridge's shared table

A sandboxed core can drive a real GPU: its renderer's GL calls leave the
sandbox through the one callback a guest is allowed, and something outside
answers them on a real context. The guest half is generated into the core; the
host half is generated into whatever runs it. This directory holds the one
thing both halves must agree on.

## Why the list is here rather than in a core

An opcode is an index into `gl-entry-points.txt`. If each core numbered its own
calls, every core would mean something different by "opcode 137", and the host
answering them would have to be built per core - which cannot work, because a
core package is a GUEST binary and the host half lives in the frontend.

So the numbering is here, in the repository both sides already share: a core
submodules this for its guest kit, and Chimera submodules it for the sandbox
host. One list, one meaning.

## The list is APPEND-ONLY

Adding a name is free. Reordering or removing one silently changes what every
already-built core meant, and a core built last year must keep working against
a frontend built today - that is the whole point of a package carrying its own
identity.

So: **new names go at the end.** A name that is no longer wanted stays where it
is, its opcode retired rather than reused. `gl-entry-points.txt` is the record;
its line number is the contract.

## How a mismatch is caught

The host tells the guest how long its list is (`CHIMERA_GL_OP_LIST_LENGTH`).
A guest built against a longer list refuses to start rather than emitting an
opcode the host has never heard of, and the core falls back to whatever it
draws with when there is no GPU. Because the list is append-only, "the host's
list is at least as long as mine" is exactly the condition for every opcode the
guest can emit to be one the host knows.

## Generating

    gen-gl-bridge.py <glad gl.h> <master list> <out dir> [--only <subset>]

`--only` generates a guest half for the entry points that core actually names,
with the master list's opcodes. Without it the whole list is generated, which is
what the host wants: it answers everything, for every core.

## The two calls that answer with a string

`glGetString` and `glGetStringi` return a pointer into the driver's memory,
which a guest cannot read. The host copies the answer into a buffer the guest
supplies, and the generated wrapper then gives it a place of its own, one per
(name, index): `gl-string-keep.inc`, pasted into every core's wrapper file.
OpenGL promises those strings are static, and renderers hold several at once
- vendor, renderer and version, to pick driver workarounds by. With one
buffer for all of them, which is how the wrapper first was, a renderer read
its version string as its vendor (Flycast logged exactly that on a GTX 1060;
Dolphin stores the three pointers too). `tests/unit/test_gl_strings.c` holds
the rule, and fails on the one-buffer version.

A core gets this when its wrapper file is generated again - at its next build
for the cores that generate it while building, and when somebody regenerates
and commits it for the ones that keep it in their repository.

## A function the driver does not provide (2026-10-18)

Every host case the generator writes asks first whether glad found the
function: a driver that lacks one leaves glad's pointer null, and the core has
a wrapper for every name, so a renderer that checks a function pointer rather
than the GL version reached a call through null and the process ended. The
case now answers 0, as a call the driver refused, and calls
`CHIMERA_GL_UNSUPPLIED(op, name)` first. The generated file defines that as
nothing unless the host defined it before including the file: Chimera's
bridge says which function, once; a core repository's own test runner needs
nothing new. The hand-written cases in Chimera's `gl_bridge.cpp` do the same.

## The names a state holds (2026-10-24)

Every GL object a renderer keeps is a number the driver gave it, and those
numbers are in guest memory, so a state holds them. After a load the host
gives the guest a fresh context, and it takes every number the guest still
holds again, empty, before the guest runs, so that no new object can get a
number an old call could still reach. The host knew those numbers only by
watching the guest make them, in its own process. A state taken by another
process, such as a project opened again with its greenzone read back from
disk, held numbers the new process had never seen. Dolphin's rebuild then
deleted a vertex array by its old number, which was the array another vertex
format had just been given, and drew black (chimera#367).

So the generated wrappers of the calls that hand out names (`NAME_MAKERS` in
the generator: `glGen*`, `glCreate*`, `glCreateProgram`, `glCreateShader`,
`glCreateShaderProgramv`) raise a table of the highest number of each kind
the guest has been given (`struct ChimeraGlNameMarks`, in the guest's own
memory), and `chimera_gl_install` tells the host where it is
(`GL_OP_NAME_MARKS`). The table is in every state, and after a load the host
keeps every number up to its marks from new objects. The kinds are the
host's, in its order. A host too old for the opcode says it has no case for
it, once, and nothing else changes.

A core picks this up when it is built again against this generator.
