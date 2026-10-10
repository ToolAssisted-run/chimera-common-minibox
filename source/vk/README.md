# The Vulkan bridge

A sandboxed core can draw on a real Vulkan device: its renderer's calls leave
the sandbox through the one callback a guest is allowed, and the host half
makes them on the machine's driver. It is the OpenGL bridge's idea (`../gl`)
for renderers that have no OpenGL - with one difference that shapes all of it.

`vk-bridge.h` is the contract and says why; this page is how it is put
together.

## No handle crosses

OpenGL names objects by small integers, so its bridge passes arguments
through untouched. Vulkan names them by handle, and a driver's handle is a
pointer: different in every process, and - once in guest memory - in every
savestate and in the order of every hash map a renderer keys by handle. So the
guest never holds one. What it holds, in a variable of the handle's type, is
a counter: the context's ordinal in the high half, an index into the host's
table in the low. An index is used once per context and never again.

Every handle is looked up on its way in, wherever it is: a parameter, a member
of a structure, an array a structure points at, a structure chained to
another. A counter that names nothing refuses the call it is in -
`VK_ERROR_DEVICE_LOST` where the call can answer, nothing where it cannot -
and the driver never sees it. `chimera_vk_host_refused` counts them.

## Generated from the registry

    gen-vk-bridge.py <vk.xml> vk-entry-points.txt <out dir>

The registry says which members are handles, which are arrays and how long,
and which structures may be chained to which. From it the generator writes
the argument blocks (`vk-bridge-ops.h`), the guest's wrappers
(`vk-bridge-guest.c`) and the host's dispatch (`vk-bridge-host.inc`).

A structure with no handle anywhere inside it is not copied: the host is in
the guest's address space and the driver reads it where it lies. One that
holds a handle is copied into an arena that lasts the call, and translated
there. A chain is walked only when something that may be chained can hold a
handle; then every structure in it that the registry knows is copied and
relinked, and one it does not know is left out, as a driver that did not know
it would.

Two things the registry cannot say are said by hand in the generator, and a
member that needs either and has neither stops it:

- **A member that is only sometimes valid** (`noautovalidity`) and may hold
  anything when it is not: a descriptor write's three arrays, a framebuffer's
  attachments when it is imageless, a primary command buffer's inheritance
  info. `MEMBER_VALID_WHEN` gives each the condition under which it is read.
- **A command that is policy** - which device, which extensions, what a
  mapping is - and is written in `vk-host.c` (`HOST_SPECIAL`).

    gen-vk-bridge.py <vk.xml> --survey <feature or extension>...

says, for every command of a version or an extension, whether it can be
generated and why not.

## The list is append-only

An opcode is 100 plus a line number in `vk-entry-points.txt`. A core built
last year must mean the same thing by the same number to a frontend built
today, so: **new names go at the end**, and a name no longer wanted stays
where it is, with a `-` put before it - its opcode retired, never reused. The
host tells a guest how long its list is, and a guest built against a longer
one does not start. An alias (`vkBindBufferMemory2KHR`) is its own line: to a
driver it is its own name.

Not in the list, and why: the window systems' commands (a core draws to an
image and reads it back), the four core commands that return a device address
or a group of devices, and every extension nobody has asked for.

## What the host decides

- **One instance, one physical device, one device** per context. The device is
  the first discrete one, or the one whose name contains `CHIMERA_VK_DEVICE`.
- **Extensions are an allow-list** (`kDeviceExtensions`): an extension is
  commands and structures this bridge would have to know.
- **No memory type is coherent.** A mapping is a buffer of the guest's own;
  `vkFlushMappedMemoryRanges` writes it out, `vkInvalidateMappedMemoryRanges`
  reads it back, and nothing else does. Every type is reported without
  `HOST_COHERENT`, so a correct renderer says when the bytes matter.
- **No callback**: allocation callbacks are replaced by none, and nothing that
  takes a function pointer is offered.
- **A load is a new context** (`chimera_vk_host_state_loaded`): everything is
  destroyed, newest first, then the device and the instance, and the ordinal
  moves - so every handle in the loaded memory names nothing. A core asks
  `chimera_vk_context_id`, sees it changed, and makes its objects again.

## One host half

`vk-host.c` is the host half for everything that runs a guest: the frontend's
engine and a core's own test runner compile this same file with the generated
`vk-bridge-host.inc`. It links against nothing - the loader is found at run
time - so a machine without Vulkan runs everything else.

## The test

`tests/vk`: one test (`vktest.h`) run twice - against the driver directly, and
from a guest through the bridge - and compared byte for byte. It clears an
image with a render pass, writes a buffer through a mapping and has the
device copy it, and then draws: two shaders, a pipeline, a descriptor set, push
constants, a vertex buffer, a second command buffer. The pointers a driver
ignores - a primary buffer's inheritance info, a uniform binding's immutable
samplers, the two arrays of a descriptor write its type does not name - point
at nothing, on purpose. Then a handle kept across a load, which must be
refused while the new context's own handle in the same place in the table is
not.

Four more builds of the runner each break one thing in the host half on
purpose (`VKB_TEST_BREAK_*`) and must fail: a flush that writes nothing (the
copied buffer and the triangle's colour both go wrong), an invalidate that
reads nothing, a handle taken from any context, and a descriptor write with
no array passed on to the driver - which kills the process inside the driver,
and is what the refusal is for. In the unbroken run that write is refused,
and it is the one refused call the run is allowed.

The shaders are kept compiled (`tests/vk/triangle-spv.h`, sources and how to
remake them in `tests/vk/shaders`), so the test needs no shader compiler. It
is skipped (77) on a machine with no Vulkan device.

Where it has run (2026-10-10): on Linux against llvmpipe (Mesa 25.2.8), by
`meson test`; and by hand on Windows against a GeForce GTX 1060 (Vulkan
1.4.312), the runner cross-built with mingw and the guest the Linux build's
own file. On both the bridged run is the direct run byte for byte - the
card rounds the two half-way colour channels down where llvmpipe rounds
them up, in both runs alike - and the flush, invalidate and stale-handle
builds fail there with the messages they fail with here. The fourth broken
build was not run on the card: it is meant to die inside the driver.

Not yet tested: a secondary command buffer, a texture sampled, a compute
pipeline, a sparse binding. Nothing runs the Windows test by itself: CI
builds no guest there, and a runner has no card.
