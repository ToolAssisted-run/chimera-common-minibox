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
