# Guest code must not use the red zone (handover note, 2026-09-21)

Status: IN PROGRESS. This note exists so that a fresh agent can finish the
work from it. Sections marked DONE are committed locally; the rest is the plan.
Push freeze is on: local commits only.

## The mechanism, in plain terms

A SysV x86-64 leaf function may keep live values in the 128 bytes below rsp
(the red zone); nothing on Linux writes there behind its back, because a
signal handler runs on a separate stack. Windows delivers an exception onto
the interrupted thread's own stack, and in this process something in that
delivery rewrites the bytes below rsp-0x28 with their content as of the
previous exception's return. A guest leaf function interrupted by a
dirty-tracking fault (or any exception) then reads back stale spills.

Measured on flycast (Prince of Persia, cpu=jit, greenzone on): LzmaDec's
`limit2`/`bufLimit` spills at rsp-0x68/-0x50 came back as zeros after one
fault, the hunk decode failed ("Sector Read miss FAD 45166"), the machine
parted from Linux at frame 137. Restoring the 128 bytes from inside the
handler gave a machine byte-identical to Linux; replaying the Windows bytes
into the Linux guest made Linux diverge; a second thread saw the guest's
store land and then be replaced before any vectored handler ran; the full
register file at the same point was identical on both hosts. Full record:
flycast `docs/PLAN.md`, entries dated 2026-09-21 (passes seven to nine).

Unnamed, after bounded search: WHICH component writes the old bytes back,
and WHICH condition of this process enables it (plain Windows processes,
miniBox blocks with rsp inside them, real TEB bounds for the whole run, and
the guest's FS base across exceptions all keep the bytes). Instruments to
resume from: `redzone-hunt-instruments.patch` and `teb-real-stack-knob.patch`
(session scratchpad; copy them into docs/ if they are to outlive it).

## The decision (Sergio, 2026-09-21)

Build every guest without a red zone (`-mno-red-zone`), in the shared
toolchain and the sysroot, enforced by a static check every core inherits.
Proved on flycast alone first: the flagged guest is byte-identical to Linux
for 1000 frames with the greenzone on.

## Where the flag goes (the choke points)

There is no single shared cross file: each core's `waterbox/setup-guest.sh`
(or `guest.mk`, or `build-guest.sh`) writes its own. Every C/C++ guest
compile does pass through the sysroot's `lib/musl-gcc.specs` - either via
the `musl-gcc` wrapper or an explicit `-specs` - so:

1. `extern/musl/tools/musl-gcc.specs.sh`: `-mno-red-zone` in the `*cc1:`
   spec (cc1 and cc1plus both run it). Reaches every core, every archive
   built through the specs, and cannot be forgotten by a new core.
2. `meson.build`: `musl_cflags` (musl is built with plain gcc, not through
   the specs) and the libstdc++ `wbx_flags`.
3. `source/guest/meson.build` `waterbox_guest_cflags` and
   `waterbox-guest.ini.in` (consumers that read them directly).
4. Rust (ruffle): a target-spec matter, not a C flag - see the survey below.
5. Sysroot archives to rebuild: musl `libc.a`, `libstdc++.a` (+fs/exp,
   `libsupc++.a`), `emulibc.c.o`, the mesa guest archives (per core,
   `setup-mesa.sh`), and the distro `libgcc.a`/`libgcc_eh.a` question.

## The static check

`source/guest/check-wbx.sh` is already run by every core's package step
(`build-package.sh` / `build-core.sh`) and by CI; the red-zone rule joins it:
disassemble, count memory operands with a negative displacement from rsp,
report by symbol, rule is zero, named allowlist for hand-written assembly.
Negative controls: red on the unflagged flycast core.wbx (3746) and on an
unflagged sysroot archive; green on the flagged build.

## Progress

- DONE: flycast-only proof (second cross file + build dir), 1000 frames.
- TODO: choke points 1-5, sysroot rebuild, check, re-proof, other cores,
  cost, docs. Each is ticked here as it lands, with its commit.
