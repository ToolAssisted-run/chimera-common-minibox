# miniBox

[![CI](https://github.com/SergioMartin86/miniBox/actions/workflows/ci.yml/badge.svg)](https://github.com/SergioMartin86/miniBox/actions/workflows/ci.yml)

The waterbox for miniHawk: a determinism sandbox in which ALL miniHawk cores
run (miniHawk is waterbox-only by design - see the miniHawk repository's
docs/design-principles.md, "THE WATERBOX-ONLY REDESIGN", and
docs/waterbox-analysis.md for the full architecture analysis).

A guest core is a static, fixed-base x86-64 ELF (".wbx") compiled against a
retargeted musl libc whose syscalls are plain calls into the host. The host
implements a FROZEN, VERSIONED machine specification: fixed address layout,
a deterministic syscall surface (constant clock, no entropy, no host
filesystem), page-granular dirty tracking against a sealed post-init
baseline, and whole-machine savestates. The same .wbx runs bit-identically
on every host OS.

Derived from the BizHawk project's waterbox
(github.com/TASEmulators/BizHawk). miniBox combines several upstream projects,
each under its own permissive license (BizHawk's waterbox - MIT; musl libc -
MIT, Rich Felker et al.; libco - public domain, byuu; LLVM libc++ etc. -
Apache-2.0 w/ LLVM exception, built not vendored). See LICENSE and
docs/ATTRIBUTION.md for the full component-by-component breakdown.

## Layout

- `source/host/` - the sandbox host, in C. This is the product: builds
  `libminiboxhost` on Linux (validated) and Windows (cross-compiled via
  mingw-w64; see `source/host/mingw-w64.ini`). A from-scratch C port of BizHawk's
  Rust waterboxhost (the historical reference, in the BizHawk repo and this
  repo's git history); no Rust or nightly toolchain is needed.
- `source/guest/` - miniBox's guest build machinery (the core-author kit):
  `linkscript.T` (fixed base 0x36f00000000, .sealed/.invis sections) and the
  meson glue (`meson.build`, `waterbox-guest.ini.in`) that builds the guest
  toolchain from the `extern/` libraries below. The musl bootstrap itself
  lives in the top-level `meson.build`; there is no separate build script.
- `extern/` - external/vendored libraries: `musl` (the guest libc, vendored
  from nattthebear/musl @ 2063abc4 with one local fix baked in - see
  docs/ATTRIBUTION.md), `emulibc` (BizHawk's guest support lib: ECL_* macros,
  sealed/invisible/plain allocators, `__wbxsysinfo`), `jsmn` (a tiny JSON
  tokenizer for the guest settings helper), `libco` (byuu's
  cothreads), `libcxx` (LLVM sysroot build scripts for C++ guests).
- `tests/` - the test suite (host unit tests + guest system tests).
- `docs/` - `MACHINE-SPEC.md` (the frozen machine contract), `ATTRIBUTION.md`
  (the component-by-component license breakdown), and debugging notes.
- `build/` - all build output (gitignored): `build/meson-linux` (which contains
  the meson-built guest toolchain under `guest-sysroot/`) and
  `build/meson-windows`.

## Building

The guest toolchain (musl) is built by meson as part of the graph - no separate
bootstrap step.

```
meson setup build/meson-linux            # builds musl, the host, and the guests
meson test  -C build/meson-linux
# C++ cores (optional): also builds libstdc++ for the guest (~75 CPU-seconds,
# fetches the GCC source matching the host compiler; see docs/ATTRIBUTION.md)
meson setup build/meson-cpp -Dguest_cpp=true
# Windows host DLL (cross-compile check; guests are skipped):
meson setup   build/meson-windows --cross-file source/host/mingw-w64.ini
ninja compile -C build/meson-windows
```

## Consumption

Chimera consumes this repository as a submodule at
`extern/tools/chimera-common-minibox` and builds the host with its own meson
arrangement, shipping it with the
frontend's OS-dependent artifacts. Core authors use `source/guest/` (with the
`extern/` libraries) to compile their emulation source into a platform-neutral
`.wbx`.

## Roadmap

1. C/C++ port of the runtime (drops the nightly-Rust requirement; validated
   against the Rust reference over shared guests and inputs).
   Phase 1 DONE (source/host/): memory block + dirty tracking + savestates +
   ELF load + interop/thunks + VFS + the syscall core; links as
   libminiboxhost.so (all 16 wbx_* exports, no external deps). A gcc-built
   conformance guest (tests/conformance/) runs end-to-end - Init, guest
   syscalls, sealed/invisible memory, seal, and a savestate round-trip all
   pass. GCC-only: no clang/lld/LLVM needed for pure-C guests.
   Phase 2 IN PROGRESS: green threads/futex/clone DONE (threading.c;
   cooperative scheduler, futex WAIT/WAKE/REQUEUE/PI, clone, thread-set
   savestate) - validated with a pthreaded guest (mutex + condvar + join +
   savestate). The Windows PAL (VEH fault handler + guard-page stack tracking +
   CreateFileMapping) and the MsHostSysVGuest win64<->sysv64 ABI adapter are
   written from the Rust reference and now runtime-tested: CI cross-builds the
   unit tests and runs them both under wine and on a real Windows runner (214
   checks). C++ guests are supported via -Dguest_cpp (libstdc++ retargeted to
   the guest); cothread support for C++ cores is still outstanding.
2. Guest ABI v1 + conformance tests, runnable entirely without miniHawk.
3. Machine specification document - the frozen contract both implementations
   are held to.
