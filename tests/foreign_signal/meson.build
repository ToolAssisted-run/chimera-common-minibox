# A host signal (a runtime's, installed before miniBox) landing while guest
# code runs with its own thread pointer: its handler must see the host's.
# Linux only: Windows has no such signals. Requires the guest toolchain
# (guarded in ../meson.build).

guest_spin_wbx = custom_target('guest_spin.wbx',
  input: 'guest_spin.c',
  output: 'guest_spin.wbx',
  command: [
    waterbox_musl_gcc, waterbox_guest_cflags, waterbox_guest_ldflags,
    '-std=c11', '-o', '@OUTPUT@', '@INPUT@', waterbox_emulibc_obj, '-lgcc',
  ],
)

run_foreign_signal = executable('run_foreign_signal', 'run_foreign_signal.c',
  dependencies: [minibox_host_dep, dependency('threads')],
)
test('foreign-signal', run_foreign_signal,
  args: [guest_spin_wbx],
  suite: 'system',
  timeout: 120,
)
