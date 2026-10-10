# The Vulkan bridge: both halves generated from the registry (see README.md).
#
#   vk_bridge_gen       [vk-bridge-ops.h, vk-bridge-guest.c, vk-bridge-host.inc]
#   vk_bridge_inc       this directory and the vendored Vulkan headers
#   vk_bridge_host_src  the host half, for whatever runs a guest
vk_headers_dir = meson.project_source_root() / 'extern' / 'vulkan-headers'
vk_bridge_gen = custom_target('vk-bridge',
  input: ['gen-vk-bridge.py', vk_headers_dir / 'registry' / 'vk.xml', 'vk-entry-points.txt'],
  output: ['vk-bridge-ops.h', 'vk-bridge-guest.c', 'vk-bridge-host.inc'],
  command: [find_program('python3'), '@INPUT0@', '@INPUT1@', '@INPUT2@', '@OUTDIR@'],
)
vk_bridge_inc = include_directories('.', '../../extern/vulkan-headers/include')
vk_bridge_host_src = files('vk-host.c')
vk_bridge_guest_src = files('vk-guest.c')
vk_bridge_source_dir = meson.current_source_dir()
vk_bridge_build_dir = meson.current_build_dir()
