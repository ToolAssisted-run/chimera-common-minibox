# Host unit tests: link the host statically (they reach internal APIs via
# minibox_internal.h) and run without any guest.

unit_tests = ['test_memblock', 'test_sha256', 'test_fs', 'test_errno', 'test_savestate', 'test_delta', 'test_fuzz', 'test_plan', 'test_tripguard', 'test_page_readable']

foreach t : unit_tests
  exe = executable(t, t + '.c', dependencies: minibox_host_static_dep)
  # a fault costs several times more on macOS (Mach's exception, then the
  # signal), and test_tripguard takes 768,000 of them
  test(t, exe, suite: 'unit', timeout: t == 'test_tripguard' and host_machine.system() == 'darwin' ? 300 : 60)
endforeach

# waterbox_slots.h is guest-kit C that compiles on the host too, which is how
# it is tested: no host library, just the header, jsmn and a cwd slots file.
slots_exe = executable(
  'test_slots',
  'test_slots.c',
  include_directories: [
    include_directories('../../source/guest/include'),
    include_directories('../../extern/jsmn'),
  ],
)
test('test_slots', slots_exe, suite: 'unit', timeout: 60)

# and the settings reader beside it, the same way
settings_exe = executable(
  'test_settings',
  'test_settings.c',
  include_directories: [
    include_directories('../../source/guest/include'),
    include_directories('../../extern/jsmn'),
  ],
)
test('test_settings', settings_exe, suite: 'unit', timeout: 60)

# source/gl/gl-string-keep.inc is guest code the GPU bridge's generator pastes
# into every core's wrapper file; plain C, so it is tested as it is.
gl_strings_exe = executable('test_gl_strings', 'test_gl_strings.c')
test('test_gl_strings', gl_strings_exe, suite: 'unit', timeout: 60)
