# Green-thread system test: a pthreaded guest (mutex + condvar + join) driven
# through the host. Requires the guest toolchain (guarded in ../meson.build).

guest_threads_wbx = custom_target('guest_threads.wbx',
  input: 'guest_threads.c',
  output: 'guest_threads.wbx',
  command: [
    waterbox_musl_gcc, waterbox_guest_cflags, waterbox_guest_ldflags,
    '-std=c11', '-o', '@OUTPUT@', '@INPUT@', waterbox_emulibc_obj, '-lgcc',
  ],
)

run_threads = executable('run_threads', 'run_threads.c',
  dependencies: minibox_host_dep,
)
test('threads', run_threads,
  args: [guest_threads_wbx],
  suite: 'system',
  timeout: 120,
)

# A host whose page is larger than the machine's (forced here, so any host runs
# it) cannot deliver the faults GuestFaultHandler waits for, and must refuse a
# guest that exports it, saying why (MACHINE-SPEC, guest fault forwarding).
test('threads-grouped-refused', run_threads,
  args: ['--refused', guest_threads_wbx],
  env: ['MB_HOST_PAGE=16384'],
  suite: 'system',
  timeout: 60,
)
