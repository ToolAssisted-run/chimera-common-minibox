# miniBox tests wired as `meson test`.
#
# Two tiers:
#  - host unit tests: link the host statically, no guest needed (always run).
#  - system tests: run a gcc-built guest .wbx through the host. The guest
#    toolchain (musl + emulibc) is built by meson itself, so these run whenever
#    the guest toolchain is built - i.e. native builds, not cross builds.

# ---- host unit tests ----
subdir('unit')

# ---- the guest runner ----
# Built ALWAYS, including cross builds: it needs only the host, and a guest .wbx
# is OS-independent, so a Linux-built guest can be run through the Windows host.
# That is the gap this closes - before it, no guest had ever executed on Windows,
# and the win64<->sysv64 boundary was only unit-tested in isolation.
subdir('runner')

# ---- guest system tests (musl+emulibc are meson-built; native only) ----
if build_guest_toolchain
  subdir('conformance')
  subdir('threads')
  if host_machine.system() == 'linux'
    subdir('foreign_signal')
  endif
  # C++ guests need the (optional) C++ guest toolchain
  if waterbox_cpp_guest
    subdir('cpp')
  endif
endif
