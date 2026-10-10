# Attribution and third-party licenses

miniBox is assembled from several upstream projects, each retaining its own
authorship and license. This file inventories every component, who authored it,
and under what terms. All components are permissively licensed and mutually
compatible; the combined work and miniBox's own new code are provided under the
MIT License (see LICENSE).

## Components vendored in this repository

### The waterbox (BizHawk) - MIT

The sandbox design and the bulk of the imported code come from the waterbox
subsystem of BizHawk (https://github.com/TASEmulators/BizHawk), Copyright (c)
the BizHawk team and contributors, MIT License. This covers:

- `source/host/` - the sandbox host, a from-scratch C port of BizHawk's Rust
  `waterbox/waterboxhost`. (The Rust original was carried in this repo's early
  history as `runtime/` and has since been removed; it lives on in BizHawk.)
- `source/host/interop_bin.c` embeds `interop.bin` - the stack-switch blob
  assembled from BizHawk's `waterbox/waterboxhost/src/context/interop.s`.
- `extern/emulibc/` - the guest support library (ECL_* macros, allocators,
  `__wbxsysinfo`).
- `extern/libcxx/` - the LLVM sysroot build scripts (the scripts are
  BizHawk's; the libraries they build are LLVM's, see below).
- `source/guest/linkscript.T` - the guest link script (fixed base, waterbox sections).
- `extern/libco/amd64.c` - the waterbox-specific rewrite of libco's amd64
  backend (derived from byuu's libco, see below).
- `docs/Notes on Debugging.md`.

### musl libc - MIT (Rich Felker and contributors)

`extern/musl` is a **vendored** copy of a waterbox-retargeted fork of musl libc
(https://github.com/nattthebear/musl @ 2063abc4, forked from
https://musl.libc.org), Copyright (c) 2005-2020 Rich Felker and the musl
contributors, MIT License. The full text and complete author list are in that
tree's `COPYRIGHT` file. The waterbox-arch additions in the fork (the `waterbox`
architecture directory, the syscall trampoline glue) are contributed under the
same MIT terms.

It is vendored rather than tracked as a submodule because upstream is no longer
maintained (no divergence to reconcile), and miniBox carries one local fix
applied directly in the tree:

- `arch/waterbox/atomic_arch.h`: `a_inc`/`a_dec` were `*p++`/`*p--` (increment
  the POINTER and discard it) instead of `(*p)++`/`(*p)--`. Harmless
  single-threaded, but with multiple guest threads it corrupts musl's `vmlock`
  counter (decremented on every `__vm_unlock`, never incremented), so a guest
  that frees memory while multithreaded deadlocks in `__vm_wait`. Found by
  miniBox's threaded guest test. This bug is present in upstream waterbox musl
  and affects BizHawk's Rust host too.

### libco - public domain (byuu)

`extern/libco/libco.h` and the original libco design are by byuu (Near),
released into the public domain (see the header of each file: "license: public
domain"). `extern/libco/amd64.c` is the waterbox rewrite of the amd64 backend
(BizHawk, MIT), built on that public-domain base.

### jsmn - MIT (Serge Zaitsev)

`extern/jsmn/jsmn.h` is jsmn, a minimal single-header JSON tokenizer,
Copyright (c) 2010 Serge Zaitsev, MIT License (full text in the file header and
`extern/jsmn/LICENSE`). The guest kit's `source/guest/include/waterbox_settings.h`
uses it to parse the host's settings channel for C cores.

### Vulkan headers and registry - Apache-2.0 OR MIT (The Khronos Group)

`extern/vulkan-headers` holds, unmodified, the part of KhronosGroup/Vulkan-Headers
the Vulkan bridge needs: `vulkan_core.h`, `vk_platform.h`, the `vk_video` headers
`vulkan_core.h` includes, and the registry `vk.xml` both halves of the bridge are
generated from (`source/vk`). The tag and commit are in its `VERSION`; the
licence texts are in its `LICENSE.md` and `LICENSES/`. Nothing of it is linked
into a guest or a host: the headers are declarations, and the registry is read
by the generator.

## Components fetched or built at build time (NOT vendored here)

### GNU libstdc++ - GPL-3.0 WITH GCC Runtime Library Exception

With `-Dguest_cpp=true`, the build fetches the GCC source matching the host
compiler and builds **only** `libstdc++-v3` for the guest (retargeted to the guest
musl and compiled with the waterbox flags, since no prebuilt C++ standard library
can link at the fixed guest base). Nothing from GCC is vendored in this
repository; the source tree is deleted after the library is installed.

libstdc++ is Copyright (c) the Free Software Foundation, licensed **GPL-3.0 with
the GCC Runtime Library Exception**. That exception exists precisely for this use:
it permits linking the runtime into programs under any license, provided they are
compiled with a compliant compiler (GCC, as here). So a C++ core linking
libstdc++ does **not** become GPL. This is the only GPL-family component miniBox
touches; everything else is MIT / public domain / Apache-2.0. Full text ships in
the GCC sources (`COPYING3`, `COPYING.RUNTIME`).

A C++ core that wants to avoid it entirely can stay freestanding (no STL,
`-fno-exceptions -fno-rtti -nostdlib++`), which needs no C++ runtime at all.

### LLVM libc++ / libc++abi / libunwind / compiler-rt - Apache-2.0 WITH LLVM exception

`extern/libcxx/*.sh` sparse-clone the LLVM project
(https://github.com/llvm/llvm-project) at a pinned tag and build the guest C++
standard library, unwinder, and compiler builtins. Those sources are Copyright
(c) the LLVM contributors, licensed Apache-2.0 with the LLVM exception. They are
downloaded during a guest toolchain build, not stored in this repository; the
license applies to the built guest artifacts.

### (Former) Rust crate dependencies

The early Rust reference (`runtime/`, now removed) depended on third-party
crates (bitflags, page_size, lazy_static, itertools, goblin, anyhow, sha2,
winapi/libc). The C port (`source/host/`) has NO external dependencies - SHA-256 and
ELF parsing are hand-written - so miniBox no longer pulls any crates.

## miniBox new work - MIT (Sergio Martin, 2026)

New code authored for miniBox - the machine specification (docs/MACHINE-SPEC.md), the
C/C++ runtime port, the reorganization, conformance tests, and build glue - is
Copyright (c) 2026 Sergio Martin, MIT License.
