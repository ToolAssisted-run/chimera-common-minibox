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
  A handle that is such a member - the set a descriptor write names, which a
  pushed write (`vkCmdPushDescriptorSet`) does not have - becomes null when
  the bridge does not know it, and the call goes on. Where a null one would
  be followed by the driver, the command says so (`PARAM_REFUSED_WHEN`):
  `vkUpdateDescriptorSets` refuses a write to a set the bridge does not know.
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
  On macOS, where MoltenVK and Mesa's KosmicKrisp can both list the same
  GPU, a driver that implements all of Vulkan comes before one that is a
  portability subset (`VK_KHR_portability_subset`).
- **Extensions are an allow-list** (`kDeviceExtensions`): an extension is
  commands and structures this bridge would have to know.
- **A command answers to every name it has.** A command that came through an
  extension and later joined a version of Vulkan has two names:
  `vkCmdSetEvent2KHR` and `vkCmdSetEvent2` are one command. A renderer asks
  for the name it was written against, so the guest's table of names answers
  every name the registry gives a command in the list, with the same function
  (no opcode of its own: the list is not longer for it). And the host asks
  the driver for a command under each of its names in turn, because a driver
  answers the newer name only to a program that asked for that version of
  Vulkan and the extension's name only where the extension is on. Before this
  (chimera issue 268) a renderer that asked for `vkCmdSetEvent2KHR` was
  answered with nothing and called it; and once it was answered, the host had
  asked a Mesa driver for `vkCmdSetEvent2` on behalf of a program that had
  asked for Vulkan 1.2, had nothing to call, and the renderer waited for an
  event that was never set.
- **A command the device lacks answers nothing** (2026-10-15, the owner's
  decision). `vkGetDeviceProcAddr` first looks in the guest's table, then asks
  the host (`VKB_OP_HAS_COMMAND`) whether the driver gave a function for the
  command under any of its names, and answers NULL when it did not, as Vulkan
  requires. It used to answer every name it knew: a call was then refused,
  and a renderer that probes for an optional feature this way took the
  answer for a yes. A host older than the question leaves it unanswered, and
  the guest answers as before. The test compares, for seven commands with
  two names, which the driver has directly and which the bridge says it has.
- **No memory type is coherent.** A mapping is a buffer of the guest's own;
  `vkFlushMappedMemoryRanges` writes it out, `vkInvalidateMappedMemoryRanges`
  reads it back, and nothing else does. Every type is reported without
  `HOST_COHERENT`, so a correct renderer says when the bytes matter.
  Making a mapping fetches what the memory holds - unless nothing has
  written it: memory the guest has flushed nothing into, allocated since
  the last time a queue was given work, holds nothing, and the guest's
  buffer is left as it is. A renderer that makes and maps its buffers before
  it draws maps a hundred megabytes of that after every load: for xemu's
  176 MiB the copy was 184 ms a load on a GeForce GTX 1060.
- **No callback**: allocation callbacks are replaced by none, and nothing that
  takes a function pointer is offered.
- **A load is a new context** (`chimera_vk_host_state_loaded`): everything is
  destroyed, newest first, then the device and the instance, and the ordinal
  moves - so every handle in the loaded memory names nothing. A core asks
  `chimera_vk_context_id`, sees it changed, and makes its objects again.

## Where the time goes

`CHIMERA_VK_STATS=1` in the host's environment makes the host half count
every command that crosses and time it, and write the totals and the
fourteen costliest commands to standard error when the bridge is shut down:

    chimera vk stats: 1932939 calls, 2.706 s in the host half and the driver
    chimera vk stats:       0.260 s       8771 calls   29660 ns each  vkFlushMappedMemoryRanges (125)

The time is the host half's and the driver's together; what a call costs on
its way out of the sandbox and back is not in it. Off, it is one comparison
a call.

## Answers that do not depend on the GPU's speed

A question about how far the GPU has got - a fence's or an event's status, a
semaphore's count, whether query results are there yet, a wait with a
timeout short of forever - gets an answer that depends on the GPU's speed,
and a core can take a different path because of it. So the host half waits
for the whole device before each such question and turns a timed wait into
a look, and the answer depends only on what was submitted; on since
2026-10-19, and `CHIMERA_VK_SETTLED=0` turns it off. The first line of
`CHIMERA_VK_STATS` says how many such waits there were. Measured 2026-10-18
on a GTX 1060: PCSX2 with a game, 900 frames,
896 waits and 0.13 s more in the host half, the same time overall; RPCS3,
600 frames, 1198 waits and 0.9% longer; Dolphin asked no such question. Two
runs of each came out the same with it and without it, so on those
programs it changed nothing that was measured. Query results that are
timestamps are still the GPU's own times.

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

Where the device has `VK_KHR_push_descriptor`, the draw is done once more with
its uniform pushed: the limit is asked for through a structure chained to the
device's properties, the command is found by name through the device, and
the write names a set that does not exist. The picture is the other uniform's
colour, the same in both runs. On a device without the extension the test says
"NOT TESTED" and passes.

The names: through the bridge the test asks for six commands by their
extension's name (`vkCmdSetEvent2KHR`, `vkCmdPipelineBarrier2KHR`,
`vkCreateRenderPass2KHR`, `vkCmdCopyBuffer2KHR`, `vkCmdSetCullModeEXT`,
`vkTrimCommandPoolKHR`) and must be given the same function as for the newer
name. Where the device has `VK_KHR_synchronization2` one of them is then
called, in both runs: the instance asks for Vulkan 1.0, a command buffer sets
an event with `vkCmdSetEvent2KHR`, and after the queue has finished the event
must be set. On a device without the extension the test says "NOT TESTED" and
passes.

Six more builds of the runner each break one thing in the host half on
purpose (`VKB_TEST_BREAK_*`) and must fail: a host that asks the driver for
each command by one name only (`NAMES`: on Mesa the event is never set, the
run stops at step 126 and a third call is counted as refused - on a driver
that answers every name to every program, NVIDIA's for one, this build passes
and the test of it cannot be used), a flush that writes nothing (the
copied buffer and the triangle's colour both go wrong), an invalidate that
reads nothing, a handle taken from any context, all memory taken for
unwritten when a mapping is made (a new mapping of a buffer the device wrote
then shows something else: the test scribbles over the old mapping first,
without flushing, so that a buffer handed out again cannot pass by luck), and
a descriptor write with no array passed on to the driver - which kills the
process inside the driver, and is what the refusal is for. In the unbroken run that write is refused,
and so is a write to a set that does not exist; they are the two refused
calls the run is allowed.

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

The pushed draw (2026-10-12) ran on both: llvmpipe and the GTX 1060 each say
32 descriptors may be pushed, and the bridged picture is the direct one.
Each of its three parts was taken out once by hand and the test failed: the
extension off the allow-list (the limit and the picture differ), the command
off the list (the run stops where it asks for it), and the rule for a write
to an unknown set (the host dies inside the driver). The names
`vkCmdBeginRenderingKHR` and `vkCmdEndRenderingKHR` are only asked for, not
called.

The names and the event (2026-10-13) ran on llvmpipe only, by `meson test`:
the test passes, and fails at step 115 with the guest's table as it was and
at step 126 with the host as it was. What the fix is for was seen on both:
RPCS3 running Tekken 6, which died calling address 0 and then, with the
guest half alone fixed, waited for ever on llvmpipe, runs on llvmpipe and on
the GTX 1060.

Four commands of extensions on the allow-list were not in the list, so a
renderer that asked for them was answered with nothing: `vkCmdSetPatchControlPointsEXT`
and `vkCmdSetLogicOpEXT` (`VK_EXT_extended_dynamic_state2`),
`vkCmdSetLineStipple` (`VK_EXT_line_rasterization`) and
`vkCmdPushDescriptorSetWithTemplate` (`VK_KHR_push_descriptor`). They are at
the end of the list now (the owner's decision, 2026-10-19), and with the last
the descriptor update templates came back: `vkCreateDescriptorUpdateTemplate`,
`vkDestroyDescriptorUpdateTemplate` and `vkUpdateDescriptorSetWithTemplate`
were retired because their data holds image views, samplers, buffers and
buffer views at offsets only the template says, and the driver was handed
the guest's handles. They are written by hand (`vk-host.c`): the host keeps
each template's entries, and each use copies the data and translates every
handle in it, as `vkUpdateDescriptorSets`'s arrays are. A template with an
entry the host cannot translate (an acceleration structure) is refused when
it is made. `VK_KHR_descriptor_update_template` is on the allow-list, for a
renderer that asked for Vulkan 1.0. A core built with the longer list needs
a Chimera at least as new.

The test draws the pushed triangle once more, its uniform pushed through a
template whose buffer sits eight bytes into the data, and compares the
picture with the direct run's; and the commands with two names it compares
take in the template commands and the three others, with their extensions
on. On llvmpipe it passes, and with the host and the list as they were it
fails: no picture, and the bridge answered nothing for six commands the
driver has.

Not yet tested: a secondary command buffer, a texture sampled, a compute
pipeline, a sparse binding. Nothing runs the Windows test by itself: CI
builds no guest there, and a runner has no card.
