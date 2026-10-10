# The Vulkan bridge, end to end (run_vk.c). The runner is built for every
# target; the guest it runs needs the guest toolchain.
run_vk_args = []
if host_machine.system() != 'windows'
  run_vk_deps = [minibox_host_dep, meson.get_compiler('c').find_library('dl', required: false)]
else
  run_vk_deps = [minibox_host_dep]
endif
run_vk = executable('run_vk', ['run_vk.c', vk_bridge_host_src, vk_bridge_gen[0], vk_bridge_gen[2]],
  include_directories: [vk_bridge_inc, include_directories('.')],
  dependencies: run_vk_deps,
  install: false,
)

# The same runner with one thing in the host half broken on purpose, each a
# test that must FAIL: a gate that cannot go red proves nothing.
vk_breaks = ['FLUSH', 'INVALIDATE', 'STALE', 'EMPTY_WRITE']
run_vk_broken = {}
foreach b : vk_breaks
  run_vk_broken += {b: executable('run_vk_broken_' + b.to_lower(),
    ['run_vk.c', vk_bridge_host_src, vk_bridge_gen[0], vk_bridge_gen[2]],
    include_directories: [vk_bridge_inc, include_directories('.')],
    dependencies: run_vk_deps,
    c_args: ['-DVKB_TEST_BREAK_' + b],
    install: false,
  )}
endforeach

if build_guest_toolchain
  vk_guest_wbx = custom_target('vk-guest.wbx',
    input: ['guest.c', vk_bridge_guest_src, vk_bridge_gen[1], vk_bridge_gen[0]],
    output: 'vk-guest.wbx',
    # the test itself is a header both runs include: without this the guest
    # kept the old test while the direct run had the new one
    depend_files: files('vktest.h', 'triangle-spv.h'),
    command: [
      waterbox_musl_gcc, waterbox_guest_cflags, waterbox_guest_ldflags,
      '-std=c11', '-D_GNU_SOURCE',
      '-I' + vk_bridge_source_dir, '-I' + vk_bridge_build_dir,
      '-I' + vk_headers_dir / 'include', '-I' + meson.current_source_dir(),
      '-o', '@OUTPUT@', '@INPUT0@', '@INPUT1@', '@INPUT2@', waterbox_emulibc_obj, '-lgcc',
    ],
  )
  test('vk-bridge', run_vk, args: [vk_guest_wbx], suite: 'system', timeout: 120)
  foreach b : vk_breaks
    test('vk-bridge-broken-' + b.to_lower(), run_vk_broken[b], args: [vk_guest_wbx],
      suite: 'system', timeout: 120, should_fail: true)
  endforeach
endif
