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
  musl_cflags = '-Werror -fvisibility=hidden -mcmodel=large ' + \
                '-mstack-protector-guard=global -fno-stack-protector -fno-pic -fno-pie -fcf-protection=none'

  # Phase 1: configure musl out-of-tree. Writes config.mak + a Makefile symlink
  # into the build root (the custom_target cwd).
  musl_config = custom_target('musl-config',
    output: 'config.mak',
    command: [
      find_program(musl_src / 'configure'),
      '--srcdir=' + musl_src,
      '--target=waterbox', '--build=waterbox', '--disable-shared',
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
  waterbox_musl_gcc = custom_target('musl-gcc',
    input: musl_config,
    output: 'musl-gcc',
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
    wbx_flags = '-mcmodel=large -mstack-protector-guard=global -fno-stack-protector -fno-pic -fno-pie -fcf-protection=none -O2'

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
if [ ! -f $D/gcc-$V.tar.xz ]; then for U in "https://mirrors.kernel.org/gnu/gcc/gcc-$V/gcc-$V.tar.xz" "https://ftpmirror.gnu.org/gcc/gcc-$V/gcc-$V.tar.xz" "https://gcc.gnu.org/pub/gcc/releases/gcc-$V/gcc-$V.tar.xz" "https://ftp.gnu.org/gnu/gcc/gcc-$V/gcc-$V.tar.xz"; do echo "fetching $U"; if curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 25 -o $D/gcc-$V.tar.xz.part "$U"; then mv $D/gcc-$V.tar.xz.part $D/gcc-$V.tar.xz; break; fi; done; fi
if [ ! -f $D/gcc-$V.tar.xz ]; then echo "could not download the GCC $V source from any mirror" >&2; exit 1; fi
# Extract the whole tree: libstdc++-v3 reaches into enough sibling directories
# (config-ml.in, libbacktrace, gcc/BASE-VER, include, ...) that a curated member
# list is fragile and would rot across GCC versions. The tree is transient - it
# is deleted after install below, leaving only the tarball and the sysroot.
if [ ! -d $D/src/gcc-$V/libstdc++-v3 ]; then tar xf $D/gcc-$V.tar.xz -C $D/src; fi
# the gthreads configure test needs gthr-default.h, which configure itself only
# generates at the END - pre-seed it, else threads come out off and the C++20
# tzdb.cc build fails ("mutex does not name a type").
echo '#include "gthr-posix.h"' > $D/gthr-inc/gthr-default.h
cd $D/build
if [ ! -f Makefile ]; then CC="gcc -specs @2@" CXX="g++ -specs @2@" CFLAGS="@3@ -I$D/gthr-inc" CXXFLAGS="@3@ -I$D/gthr-inc" $D/src/gcc-$V/libstdc++-v3/configure --host=x86_64-linux-musl --build=x86_64-pc-linux-gnu --prefix=@4@ --disable-shared --enable-static --disable-multilib --disable-libstdcxx-pch --disable-nls; fi
make -j"$(nproc)"
make install
# everything needed now lives in the sysroot; reclaim the ~1.1GB source tree and
# the build tree (the tarball is kept so a rebuild does not re-download)
cd $D
rm -rf $D/src $D/build
touch @5@
'''.format(cpp_dir, gcc_version, musl_specs, wbx_flags, waterbox_sysroot,
           meson.current_build_dir() / 'libstdcxx-installed.stamp')],
    )
    waterbox_gxx_include = waterbox_sysroot / 'include' / 'c++' / gcc_version
  endif
endif

subdir('source/guest')   # exposes the waterbox_guest_* variables (guest .wbx build)

# Tests are opt-in for subproject consumers; on by default for a standalone build.
if not meson.is_subproject()
  subdir('tests')
endif
