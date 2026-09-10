# Host unit tests: link the host statically (they reach internal APIs via
# minibox_internal.h) and run without any guest.

unit_tests = ['test_memblock', 'test_sha256', 'test_fs', 'test_savestate', 'test_delta', 'test_fuzz']

foreach t : unit_tests
  exe = executable(t, t + '.c', dependencies: minibox_host_static_dep)
  test(t, exe, suite: 'unit', timeout: 60)
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
