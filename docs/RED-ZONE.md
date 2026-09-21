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

## What the flag reached, per build path and per archive

Every C and C++ guest compile in every core passes through the sysroot's
`lib/musl-gcc.specs`, either through the `musl-gcc` wrapper or an explicit
`-specs`, so the `*cc1` entry is the one place that reaches all of them.
Verified with a leaf that spills 22 words at `-O2`: none through the specs,
for `gcc` and for `g++` (the entry is read by cc1 and cc1plus alike).

| build path | how it gets the flag | verified |
|---|---|---|
| per-core meson cross files (flycast, quickernes, pcsx2, ppsspp, gpgx, snes9x, stella, opera, dosbox-x, applewin, ares, xemu) | `-specs .../musl-gcc.specs` already in their `c_args`/`cpp_args` | flycast, quickernes, pcsx2 rebuilt and clean |
| Makefile guests (dolphin, rpcs3, eka2l1) | `SPECS := -specs $(SR)/lib/musl-gcc.specs` in `guest.mk` | not rebuilt here |
| shell guests (pcem) | `-specs $SR/lib/musl-gcc.specs` in `GUESTFLAGS` | not rebuilt here |
| xemu's wrapper compilers | `guest-cc`/`guest-cxx` exec gcc with the specs | not rebuilt here |
| mesa guest archives (flycast, pcsx2, ruffle) | `gw-cc`/`gw-cxx` wrappers, same specs | all three rebuilt, 18 archives each, clean |
| the Rust guest (ruffle) | NOT a C flag: `disable-redzone: true` in `waterbox-guest.json`, with `build-std` so std is rebuilt too | rebuilt: 16657 -> 0, and no Rust-mangled symbol remains |
| miniBox's own `emulibc.c.o`, `cxxglue.c.o` | `waterbox_guest_cflags` | rebuilt, clean |

Sysroot archives, before and after (memory operands below rsp):

| archive | how it is built | before | after |
|---|---|---|---|
| `libc.a` (musl) | plain gcc, so `musl_cflags` in meson.build carries the flag | 217 | 0 |
| `libstdc++.a`, `libstdc++fs.a`, `libstdc++exp.a`, `libsupc++.a` | the libstdc++ target's `wbx_flags` | 0 after the lint's lea fix | 0 |
| `crt1.o`, `Scrt1.o`, `crti.o`, `crtn.o` | musl | 0 | 0 |
| `libgcc.a`, `libgcc_eh.a` | the HOST gcc's own, not rebuilt | 1 (`__strub_leave`) | allowlisted |

Two hand-written waterbox routines used the red zone on purpose and were
changed to push a scratch word instead, the idiom `__fesetround` in the same
file already used: `src/fenv/waterbox/fenv.s` (`feclearexcept`,
`feraiseexcept`, MXCSR scratch) and `src/math/waterbox/exp2l.s` (`expm1l`, a
float constant). Nothing else in musl's assembly addresses below rsp.

`libgcc.a` is the one archive that cannot be rebuilt here - it belongs to the
compiler installation - and one of its members, `__strub_leave`, keeps a word
below rsp. It is the `-fstrub` stack-scrubbing runtime, no guest is built with
`-fstrub`, and an archive member is linked only when something references it,
so it never enters a guest image. That is the whole of
`red-zone-allowlist.txt`; empty the file and the check goes red on exactly it.

## What the check counts, and two things it does not

The rule is zero memory operands with a negative displacement from rsp,
reported by symbol. Two forms are deliberately not counted, each after a
false positive:

- `lea` is address arithmetic, not a memory access. `lea -0x8(%rsp),%rsp` IS
  the stack allocation, and `lea -0x1000(%rsp),%rax` is how a variable-length
  array is set up. Counting them called libstdc++ and musl's `getcwd` guilty.
- an INDEXED operand such as `-0x8(%rsp,%rax,8)` resolves above rsp for any
  nonzero index and cannot be judged without running the code. Counting those
  turned compiler-generated frame indexing into 65 false violations.

## The proof on flycast

Prince of Persia: Arabian Nights, `cpu=jit`, 1000 frames, the reproduction
that found this:

| run | result |
|---|---|
| flagged guest (core + sysroot + mesa), Windows, greenzone on | byte-identical to Linux |
| flagged guest, Windows, greenzone off | byte-identical to Linux |
| flagged guest on Linux vs the UNFLAGGED guest's Linux reference | byte-identical - the machine does not depend on frame layout |
| unflagged guest, Windows, greenzone on, same host build | parts at frame 137 |

Cost, 1000 frames through run-wbx on Linux, three runs each alternating:
unflagged 55.64 / 55.67 / 55.50 s, flagged 55.59 / 55.33 / 55.91 s. The means
differ by 0.01 s, which is inside the run-to-run spread of either set. The
guest image grew by 92 KB on 94 MB.

## Progress

- DONE: the flag at every choke point, the sysroot rebuilt, the two musl
  assembly routines fixed, the check and its allowlist, the negative
  controls, the flycast re-proof, quickernes + pcsx2 + ruffle rebuilt and
  gated, the cost number. All of the above is measured, not assumed.
- NOT DONE, for CI after the push: dolphin, rpcs3, eka2l1, pcem, xemu,
  ppsspp, gpgx, snes9x, stella, opera, dosbox-x, applewin, ares,
  quickerneshawk, angrylion. Each reaches the flag through the specs, and
  none was rebuilt here.
- Still unnamed: the component that rewrites the bytes, and the condition
  that enables it. The flag removes the exposure; it does not explain it.
