# C++ (Tier 2) guest system test. Reached only when -Dguest_cpp=true built the
# C++ guest toolchain (guarded in ../meson.build).
# Uses the shared waterbox_guest_cxx_* variables from source/guest/meson.build.

guest_cpp_wbx = custom_target('guest_cpp.wbx',
  input: 'guest_cpp.cpp',
  output: 'guest_cpp.wbx',
  command: [
    waterbox_guest_link + [waterbox_musl_gxx], waterbox_guest_cxxflags, waterbox_guest_cxx_ldflags,
    '-std=c++17', '-o', '@OUTPUT@', '@INPUT@',
    waterbox_cxxglue_obj, waterbox_emulibc_obj, waterbox_guest_cxx_libs,
  ],
)

run_cpp = executable('run_cpp', 'run_cpp.c',
  dependencies: minibox_host_dep,
)
test('cpp-guest', run_cpp,
  args: [guest_cpp_wbx],
  suite: 'system',
  timeout: 120,
)
