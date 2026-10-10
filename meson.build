# miniBox - a determinism sandbox (the waterbox for Chimera).
#
# This top-level project builds the host runtime and wires the tests. The guest
# toolchain (musl + emulibc) and guest cores are built through the waterbox-guest
# cross machinery under source/guest/ (see source/guest/meson.build and
# source/guest/waterbox-guest.ini.in), which is separate because a guest is compiled
# for the sandbox's fake machine, not the host.
#
# As a subproject:
#   minibox = subproject('miniBox')
#   dep = minibox.get_variable('minibox_host_dep')
project('miniBox', 'c',
  version: '0.1.0',
  license: 'MIT',
  default_options: ['c_std=c11', 'warning_level=2', 'default_library=both'],
)

subdir('source/host')

# ---------------------------------------------------------------------------
# Guest toolchain: build the vendored musl (extern/musl) into the build dir.
#
# musl is autotools (configure + make install), so it is driven here at the
# top level - where a custom_target's working directory equals the build root,
# which is what musl's out-of-tree `configure` writes into. Everything lands
# under the build dir; there is no separate bootstrap script and no manual step.
#
# The guest libc is always built with the host gcc (the guest is a fake-machine
# target, not a host binary), so this is skipped for cross builds (e.g. the
# Windows host-DLL compile-check), which do not build or run guests.
# ---------------------------------------------------------------------------
build_guest_toolchain = not meson.is_cross_build()

if build_guest_toolchain
  waterbox_sysroot = meson.current_build_dir() / 'guest-sysroot'
  musl_src         = meson.current_source_dir() / 'extern' / 'musl'
  # The frozen musl CFLAGS (from extern/musl/wbox_configure.sh).
  # -mno-red-zone: a guest may be interrupted by a dirty-tracking fault at any
  # instruction, and on Windows that exception is delivered onto the guest's own
  # stack, where the bytes below rsp do not survive it (docs/RED-ZONE.md). So no
  # guest code, libc included, may keep anything below rsp. The same flag sits
  # in the musl-gcc specs (*cc1) for everything compiled through them.
  #
  # The guest runs directly on the host's CPU, so it is built for that CPU: the
  # x86-64 machine the spec describes, or the aarch64 one (arch/waterbox_aarch64
  # in musl). waterbox_cpu_flags are each CPU's frozen code-generation flags:
  #   x86-64   large code model (the guest sits above 2 GiB and the small model
  #            cannot reach it), no red zone, no CET;
  #   aarch64  the default small model (addressing is pc-relative: any base
  #            works), no return-address signing (keyed per process - a signed
  #            pointer in a savestate is another pointer in the next process),
  #            no outline atomics (they ask the CPU what it has), and the
  #            arithmetic of the x86-64 machine: no fused multiply-add, signed
  #            char. The same flags sit in the musl-gcc specs (*cc1).
  if host_machine.cpu_family() == 'aarch64'
    waterbox_musl_target = 'waterbox_aarch64'
    waterbox_guest_triplet = 'aarch64-linux-musl'
    waterbox_cpu_flags = ['-mbranch-protection=none', '-mno-outline-atomics', '-ffp-contract=off', '-fsigned-char']
  elif host_machine.cpu_family() == 'x86_64'
    waterbox_musl_target = 'waterbox'
    waterbox_guest_triplet = 'x86_64-linux-musl'
    waterbox_cpu_flags = ['-mcmodel=large', '-mno-red-zone']
  else
    error('miniBox runs on x86-64 and aarch64 only, not ' + host_machine.cpu_family())
  endif
  waterbox_common_flags = ['-mstack-protector-guard=global', '-fno-stack-protector', '-fno-pic', '-fno-pie']
  if host_machine.cpu_family() == 'x86_64'
    waterbox_common_flags += ['-fcf-protection=none']
  endif
  musl_cflags = ' '.join(['-Werror', '-fvisibility=hidden'] + waterbox_cpu_flags + waterbox_common_flags)

  # Phase 1: configure musl out-of-tree. Writes config.mak + a Makefile symlink
  # into the build root (the custom_target cwd).
  musl_config = custom_target('musl-config',
    output: 'config.mak',
    command: [
      find_program(musl_src / 'configure'),
      '--srcdir=' + musl_src,
      '--target=' + waterbox_musl_target, '--build=' + waterbox_musl_target, '--disable-shared',
      '--prefix=' + waterbox_sysroot,
      '--bindir=' + meson.current_build_dir(),      # musl-gcc -> a trackable build-root path
      '--libdir=' + waterbox_sysroot / 'lib',
      '--includedir=' + waterbox_sysroot / 'include',
      '--syslibdir=' + waterbox_sysroot / 'syslib',
    ],
    env: {'CC': 'gcc', 'CFLAGS': musl_cflags},
  )

  # Phase 2: build + install musl (reads config.mak from the same build root).
  # The wrapper lands at <build>/musl-gcc; headers/libs under guest-sysroot/.
  # depend_files on the vendored musl sources so an edit (e.g. a syscall-glue
  # fix in arch/waterbox) forces the sysroot to rebuild. Without this, make's
  # own outputs are invisible to ninja and a fixed header silently ships as a
  # stale libc.a (cost a day chasing "Rust file IO is broken" - it was not).
  musl_dep_files = run_command('sh', '-c',
    'find ' + musl_src / 'arch' / waterbox_musl_target + ' ' + musl_src / 'src' + ' ' + musl_src / 'crt' + ' ' + musl_src / 'tools' +
    ' -name "*.h" -o -name "*.c" -o -name "*.s" -o -name "*.S" -o -name "*.sh" 2>/dev/null',
    check: false).stdout().strip().split('\n')
  waterbox_musl_gcc = custom_target('musl-gcc',
    input: musl_config,
    output: 'musl-gcc',
    depend_files: musl_dep_files,
    command: [find_program('make'), '-j', 'install'],
    console: true,
  )

  # -------------------------------------------------------------------------
  # C++ guest toolchain (-Dguest_cpp=true): libstdc++ retargeted to the guest.
  #
  # No prebuilt C++ stdlib can ever work here: it must be built against the guest
  # musl AND with the waterbox flags (-mcmodel=large -fno-pic), or it cannot link
  # at the fixed guest base. libstdc++ supports this directly - its configure.host
  # maps linux-musl* to os/generic, avoiding the glibc coupling.
  #
  # libstdc++ must match the host GCC, so the matching source is fetched (~84MB)
  # and extracted transiently; the whole build is ~75 CPU-seconds and lands in
  # guest-sysroot alongside musl. Off by default (-Dguest_cpp): pure-C cores do
  # not need it. CI should cache guest-sysroot keyed on the gcc version + the
  # musl commit + these flags.
  #
  # This one target shells out (via sh -c) because autotools writes into its
  # working directory, and a custom_target's cwd is the build root, which musl
  # already owns. It is still fully meson-driven - no manual step, no script file.
  # -------------------------------------------------------------------------
  waterbox_cpp_guest = get_option('guest_cpp')
  if waterbox_cpp_guest
    gcc_version = run_command('gcc', '-dumpfullversion', check: true).stdout().strip()
    cpp_dir = meson.current_build_dir() / 'cpp-toolchain'
    gcc_srcdir = cpp_dir / 'src' / 'gcc-' + gcc_version
    musl_specs = waterbox_sysroot / 'lib' / 'musl-gcc.specs'
    # Same frozen guest flags the .wbx itself is compiled with.
    wbx_flags = ' '.join(waterbox_cpu_flags + waterbox_common_flags + ['-O2'])

    waterbox_libstdcxx = custom_target('libstdcxx',
      input: waterbox_musl_gcc,           # needs the guest musl headers/libs first
      output: 'libstdcxx-installed.stamp',
      console: true,
      # NOTE: no backslashes anywhere below - meson mangles them inside strings,
      # so every command must fit on one line.
      command: [find_program('sh'), '-c', '''
set -e
D=@0@
V=@1@
mkdir -p $D/src $D/build $D/gthr-inc
# The matching GCC source, fetched once. Several mirrors are tried: ftp.gnu.org
# is regularly unreachable from CI runners (connect timeouts), so it is last.
# A distribution GCC may report a version no release carries: Fedora's 16.2.1
# is a snapshot of the 16.2 branch, after 16.2.0. Its release (x.y.0) is then
# the source, and the tree is stamped with the host's version below, so the
# headers land under include/c++/$V as every consumer expects.
for S in $V $(echo $V | sed "s/[.][0-9]*$/.0/"); do if [ ! -f $D/gcc-$S.tar.xz ]; then for U in "https://mirrors.kernel.org/gnu/gcc/gcc-$S/gcc-$S.tar.xz" "https://ftpmirror.gnu.org/gcc/gcc-$S/gcc-$S.tar.xz" "https://gcc.gnu.org/pub/gcc/releases/gcc-$S/gcc-$S.tar.xz" "https://ftp.gnu.org/gnu/gcc/gcc-$S/gcc-$S.tar.xz"; do echo "fetching $U"; if curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 25 -o $D/gcc-$S.tar.xz.part "$U"; then mv $D/gcc-$S.tar.xz.part $D/gcc-$S.tar.xz; break; fi; done; fi; if [ -f $D/gcc-$S.tar.xz ]; then break; fi; done
if [ ! -f $D/gcc-$S.tar.xz ]; then echo "could not download the GCC $V source (or its release) from any mirror" >&2; exit 1; fi
# Extract the whole tree: libstdc++-v3 reaches into enough sibling directories
# (config-ml.in, libbacktrace, gcc/BASE-VER, include, ...) that a curated member
# list is fragile and would rot across GCC versions. The tree is transient - it
# is deleted after install below, leaving only the tarball and the sysroot.
if [ ! -d $D/src/gcc-$S/libstdc++-v3 ]; then tar xf $D/gcc-$S.tar.xz -C $D/src; fi
echo $V > $D/src/gcc-$S/gcc/BASE-VER
# (CFLAGS -std=gnu17: GCC 15 and later compile C as C23, where musl's old-style
# `char *basename();` means no arguments and clashes with libiberty's prototype
# in the few C files libstdc++ builds - libbacktrace, for <stacktrace>.)
# the gthreads configure test needs gthr-default.h, which configure itself only
# generates at the END - pre-seed it, else threads come out off and the C++20
# tzdb.cc build fails ("mutex does not name a type").
echo '#include "gthr-posix.h"' > $D/gthr-inc/gthr-default.h
cd $D/build
if [ ! -f Makefile ]; then CC="gcc -specs @2@" CXX="g++ -specs @2@" CFLAGS="@3@ -std=gnu17 -I$D/gthr-inc" CXXFLAGS="@3@ -I$D/gthr-inc" $D/src/gcc-$S/libstdc++-v3/configure --host=@6@ --build=$(gcc -dumpmachine) --prefix=@4@ --disable-shared --enable-static --disable-multilib --disable-libstdcxx-pch --disable-nls; fi
make -j"$(nproc)"
make install
# libstdc++ installs into the compiler's multilib directory, which is lib64 on
# Fedora (lib on Debian); everything that links a guest looks in lib
if [ -d @4@/lib64 ]; then mv @4@/lib64/* @4@/lib/; rmdir @4@/lib64; fi
# everything needed now lives in the sysroot; reclaim the ~1.1GB source tree and
# the build tree (the tarball is kept so a rebuild does not re-download)
cd $D
rm -rf $D/src $D/build
touch @5@
'''.format(cpp_dir, gcc_version, musl_specs, wbx_flags, waterbox_sysroot,
           meson.current_build_dir() / 'libstdcxx-installed.stamp', waterbox_guest_triplet)],
    )
    waterbox_gxx_include = waterbox_sysroot / 'include' / 'c++' / gcc_version
  endif
endif

subdir('source/guest')   # exposes the waterbox_guest_* variables (guest .wbx build)

# Tests are opt-in for subproject consumers; on by default for a standalone build.
if not meson.is_subproject()
  subdir('tests')
endif
