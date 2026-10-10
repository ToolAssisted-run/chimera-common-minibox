/* The seam between a sandboxed machine and a real Vulkan device.
 *
 * The shape is the OpenGL bridge's (../gl/gl-bridge.h): a guest may call one
 * function pointer the host registers with the sandbox, six integers in and
 * one out, so every Vulkan call crosses as (opcode, pointer to an argument
 * block in GUEST memory). The host is in the same address space and reads
 * what the block points at where it lies.
 *
 * What is different is what crosses back. OpenGL names its objects by small
 * integers. Vulkan names them by handle, and a driver's handle is a pointer
 * into the driver: unreadable by a guest, different in every process, and it
 * would be written into guest memory - into savestates, and into whatever a
 * renderer keeps keyed by handle. So no driver handle is ever given to a
 * guest. The host keeps a table; what the guest holds, in a variable of the
 * handle's type, is a counter into it (the context's ordinal in the high
 * half, an index in the low), and every handle is looked up on its way in.
 * A counter that names nothing - one a savestate carried in from a context
 * that is gone - refuses the call it is in: VK_ERROR_DEVICE_LOST where the
 * call can answer, nothing where it cannot. The driver never sees it.
 *
 * Three more things a guest does not get:
 *
 * - A pointer into the driver's memory. vkMapMemory gives the guest a buffer
 *   of its OWN, and the host copies between that and the real mapping when
 *   the guest says the bytes matter: vkFlushMappedMemoryRanges writes them
 *   out and vkInvalidateMappedMemoryRanges reads them back, and nothing else
 *   does - not unmapping, not submitting. So that a correct renderer says
 *   so, every memory type is reported WITHOUT
 *   VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, which is the promise that it would
 *   not have to. A renderer that writes and does not flush draws nothing.
 * - A window. No surface or swapchain extension is offered: a core draws to
 *   an image and reads it back.
 * - A callback. Allocation callbacks are replaced by none, and no debug
 *   messenger can be made: the driver would call into the guest on its own
 *   stack, outside the sandbox's ABI.
 *
 * WHAT THIS COSTS is what the OpenGL bridge costs. The device is outside the
 * sandbox, so it is outside the savestate and different on every machine; a
 * core drawing this way must say so. And a load is a new context: everything
 * the renderer held is gone, and it finds that out by asking which context
 * it is on (chimera_vk_context_id) and making its objects again.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

/* Opcodes below 100 are the bridge talking about itself; 100 and up are the
 * Vulkan commands, numbered by the master list (see README.md). */
enum {
	/* How many lines the HOST's master list has. The list is append-only,
	 * so a host whose list is at least as long as the guest's knows every
	 * opcode the guest can emit. */
	VKB_OP_LIST_LENGTH = 1,

	/* Which context this is. Any two differ, in this process or another;
	 * zero is "cannot tell". A renderer that keeps this beside its objects
	 * can see, after a savestate load, that they were another context's. */
	VKB_OP_CONTEXT_ID = 2,

	/* args: struct vkb_description_args. The device the calls land on, in
	 * words, for a log. */
	VKB_OP_DESCRIPTION = 3,

	/* args: struct vkb_map_attach_args. The second half of vkMapMemory:
	 * the guest names the buffer it will use as the mapping, and the host
	 * fills it with what the memory holds. */
	VKB_OP_MAP_ATTACH = 4
};

struct vkb_description_args {
	uint64_t out;       /* guest pointer to a char buffer */
	uint32_t size;
};

struct vkb_map_attach_args {
	uint64_t memory;    /* the VkDeviceMemory, as the guest holds it */
	uint64_t shadow;    /* guest pointer to as many bytes as the mapping has */
};

/* The callback's shape, as the sandbox defines it. */
typedef uint64_t (*chimera_vk_bridge_fn)(uint64_t op, uint64_t a, uint64_t b,
                                         uint64_t c, uint64_t d, uint64_t e);

#ifdef __cplusplus
extern "C" {
#endif

/* ---- the guest half (vk-guest.c and the generated vk-bridge-guest.c) ---- */

/* Point the wrappers at the host's callback. False when there is none, or
 * when the host's list is shorter than the one this core was built against. */
bool chimera_vk_install(chimera_vk_bridge_fn bridge);

/* What a loader asks for: the wrapper for a command, or null when this
 * bridge does not carry it - which is what a driver answers for a command it
 * does not have. vkGetInstanceProcAddr and vkGetDeviceProcAddr are answered
 * from the same table. */
void *chimera_vk_lookup(const char *name);

/* Which context the calls are landing on (VKB_OP_CONTEXT_ID); zero with no
 * bridge. */
uint64_t chimera_vk_context_id(void);

/* The device, in words. */
void chimera_vk_description(char *out, uint32_t size);

/* After a load, when the context is seen to have changed: the buffers this
 * half lent out as mappings belonged to memory that no longer exists. */
void chimera_vk_forget_mappings(void);

/* One call across. */
uint64_t chimera_vk_call(uint32_t op, void *args);

#ifdef __cplusplus
}
#endif
