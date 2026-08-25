# The waterbox guest toolchain, exposed to meson consumers.
#
# musl (extern/musl, the guest libc) is built into the build dir by the
# top-level meson.build; this file builds emulibc against it and exports the
# pieces a consumer needs to compile a .wbx guest via a custom_target:
#
#   minibox = subproject('miniBox')
#   guest = custom_target('core.wbx',
#     input: 'core.c', output: 'core.wbx',
#     command: [ minibox.get_variable('waterbox_musl_gcc'),
#                minibox.get_variable('waterbox_guest_cflags'),
#                minibox.get_variable('waterbox_guest_ldflags'),
#                '-o', '@OUTPUT@', '@INPUT@',
#                minibox.get_variable('waterbox_emulibc_obj'), '-lgcc' ])
#
# A generated cross-file (waterbox-guest.ini) is also emitted for consumers that
# prefer building the guest as a separate cross-compiled meson project.
#
# All of this is native-only: a guest targets the fake machine and is built with
# the host gcc, so it is skipped for cross builds (build_guest_toolchain is set
# in the top-level meson.build).

if not build_guest_toolchain
  subdir_done()
endif

waterbox_emulibc_dir = meson.project_source_root() / 'extern' / 'emulibc'
waterbox_guestkit_inc = meson.current_source_dir() / 'include'     # miniBox guest kit headers
waterbox_jsmn_dir     = meson.project_source_root() / 'extern' / 'jsmn'
waterbox_linkscript  = meson.current_source_dir() / 'linkscript.T'

# The frozen guest flags (BizHawk waterbox COMMONFLAGS; C, no C++/LTO).
waterbox_guest_cflags = [
  '-fvisibility=hidden', '-I' + waterbox_emulibc_dir,
  '-I' + waterbox_guestkit_inc, '-I' + waterbox_jsmn_dir,
  '-Wall', '-mcmodel=large',
  '-mstack-protector-guard=global', '-fno-stack-protector', '-fno-pic', '-fno-pie', '-fcf-protection=none',
  '-O2', '-DNDEBUG',
]
waterbox_guest_ldflags = [
  '-static', '-no-pie', '-Wl,--eh-frame-hdr,-O2', '-T', waterbox_linkscript,
]

# emulibc.o is a meson build artifact, compiled with the just-built musl-gcc.
# Passing the musl-gcc custom_target as command[0] makes ninja build musl first.
waterbox_emulibc_ct = custom_target('emulibc.c.o',
  input: waterbox_emulibc_dir / 'emulibc.c',
  output: 'emulibc.c.o',
  command: [waterbox_musl_gcc, '-c', waterbox_guest_cflags, '-std=c11', '-o', '@OUTPUT@', '@INPUT@'],
)
waterbox_emulibc_obj = waterbox_emulibc_ct

# ---------------------------------------------------------------------------
# C++ guests (-Dguest_cpp=true). The link recipe below is not obvious and is
# exported so cores do not have to rediscover it:
#   * library ORDER matters: -lstdc++ -lgcc -lgcc_eh -lc, with libc LAST.
#   * -Wl,--no-relax: the large code model otherwise fails to convert GOTPCREL.
#   * -Wl,-u,pthread_*: libgcc_eh references these WEAKLY, and weak refs do not
#     pull members out of an archive - they would stay undefined at address 0,
#     and a PC-relative reloc from the 0x36f00000000 base cannot reach it.
#   * cxxglue.o supplies __dso_handle and _dl_find_object (see cxxglue.c).
# Cores compile with -fno-exceptions -fno-rtti by default (Tier 2: STL, no EH);
# exceptions would additionally need the unwinder wired at the fixed base.
# ---------------------------------------------------------------------------
if waterbox_cpp_guest
  waterbox_musl_gxx = 'g++'
  waterbox_guest_cxxflags = waterbox_guest_cflags + [
    '-specs', waterbox_sysroot / 'lib' / 'musl-gcc.specs',
    '-I' + waterbox_gxx_include,
    '-I' + waterbox_gxx_include / 'x86_64-linux-musl',
    '-fno-exceptions', '-fno-rtti',
  ]
  waterbox_guest_cxx_ldflags = [
    '-static', '-no-pie', '-Wl,--eh-frame-hdr,-O2,--no-relax',
    '-T', waterbox_linkscript,
    '-Wl,-u,pthread_once', '-Wl,-u,pthread_cond_wait',
    '-Wl,-u,pthread_cond_broadcast', '-Wl,-u,pthread_key_create',
  ]
  # Linked AFTER the objects; order is load-bearing (see above).
  waterbox_guest_cxx_libs = [
    '-L' + waterbox_sysroot / 'lib', '-lstdc++', '-lgcc', '-lgcc_eh', '-lc',
  ]
  waterbox_cxxglue_obj = custom_target('cxxglue.c.o',
    input: 'cxxglue.c',
    output: 'cxxglue.c.o',
    command: [waterbox_musl_gcc, '-c', waterbox_guest_cflags, '-std=c11', '-o', '@OUTPUT@', '@INPUT@'],
    depends: waterbox_libstdcxx,
  )
endif

# Emit a cross-file for consumers who want to build the guest as a cross project.
configure_file(
  input: 'waterbox-guest.ini.in',
  output: 'waterbox-guest.ini',
  configuration: {
    'MUSL_GCC': waterbox_musl_gcc.full_path(),
    'EMULIBC_INC': waterbox_emulibc_dir,
    'GUESTKIT_INC': waterbox_guestkit_inc,
    'JSMN_INC': waterbox_jsmn_dir,
    'EMULIBC_OBJ': waterbox_emulibc_ct.full_path(),
    'LINKSCRIPT': waterbox_linkscript,
  },
)
