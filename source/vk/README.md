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
from a guest through the bridge - and compared byte for byte; then a handle
kept across a load, which must be refused while the new context's own handle
in the same place in the table is not. It needs no shader, so no shader
compiler. Three more builds of the runner each break one thing in the host
half on purpose (`VKB_TEST_BREAK_*`: a flush that writes nothing, an
invalidate that reads nothing, a handle taken from any context) and must fail.

It is skipped (77) on a machine with no Vulkan device. Not yet tested: a
pipeline and a draw, a descriptor set, a secondary command buffer, a real
graphics card, and a Windows host beyond compiling.
