# System test: build a gcc guest .wbx and run it through the host end-to-end.
# Reached only when the guest toolchain is present (guarded in ../meson.build).
# Uses the shared waterbox_guest_* variables from source/guest/meson.build.

guest_wbx = custom_target('guest.wbx',
  input: 'guest.c',
  output: 'guest.wbx',
  command: [
    waterbox_musl_gcc, waterbox_guest_cflags, waterbox_guest_ldflags,
    '-std=c11', '-o', '@OUTPUT@', '@INPUT@', waterbox_emulibc_obj, '-lgcc',
  ],
)

# run_guest comes from ../runner (built for every target, cross included)
test('conformance-guest', run_guest,
  args: [guest_wbx],
  suite: 'system',
  timeout: 120,
)

# x86-64 only: the %fs a host may drop, and FSGSBASE that may be missing.
# aarch64's thread pointer is always the user's and is never lost.
if host_machine.cpu_family() == 'x86_64'
# Dropped-%fs repair: guest toolchain only (Linux), like the guest itself.
test('conformance-fs-repair', run_guest,
  args: ['--fs-repair-child', guest_wbx],
  suite: 'system',
  timeout: 120,
)

# Probe forced off: the FSGSBASE instructions must be unreachable, so the
# whole standard flow has to pass without them.
test('conformance-probe-off', run_guest,
  args: ['--probe-off', guest_wbx],
  suite: 'system',
  timeout: 180,
)
endif

# Spec v3 (virtual time): a guest declaring __wbx_machine_spec = 3.
guest_v3_wbx = custom_target('guest-v3.wbx',
  input: 'guest-v3.c',
  output: 'guest-v3.wbx',
  command: [
    waterbox_musl_gcc, waterbox_guest_cflags, waterbox_guest_ldflags,
    '-std=c11', '-o', '@OUTPUT@', '@INPUT@', waterbox_emulibc_obj, '-lgcc',
  ],
)
test('conformance-v3', run_guest,
  args: ['--v3', guest_v3_wbx],
  suite: 'system',
  timeout: 180,
)
