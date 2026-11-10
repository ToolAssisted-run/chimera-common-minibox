# Host unit tests: link the host statically (they reach internal APIs via
# minibox_internal.h) and run without any guest.

unit_tests = ['test_fault_stack', 'test_memblock', 'test_sha256', 'test_fs', 'test_errno', 'test_savestate', 'test_delta', 'test_fuzz', 'test_plan', 'test_tripguard', 'test_page_readable']

foreach t : unit_tests
  exe = executable(t, t + '.c', dependencies: minibox_host_static_dep)
  # a fault costs more on macOS (Mach's exception, then the signal): 1.8 us
  # on GitHub's Apple silicon Mac and 26 to 44 us on its Intel one, against
  # 2.3 us on Linux here, so the tests that take many have more time there
  # (test_memblock took 29 seconds on the Intel Mac once and over 60 the next
  # run). test_tripguard's 1500 rounds of 512 faults take 30 seconds on the
  # first and eleven minutes on the second, which runs 300.
  darwin = host_machine.system() == 'darwin'
  test(t, exe, suite: 'unit', timeout: darwin ? 300 : 60,
    env: darwin and t == 'test_tripguard' and host_machine.cpu_family() == 'x86_64' ? ['MB_TEST_FAULT_ROUNDS=300'] : [])
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
