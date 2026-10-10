/* The Vulkan bridge's test, as a guest: vktest.h run through the bridge. */
#include <emulibc.h>
#include <stdint.h>
#include "vk-bridge.h"
#include "vktest.h"

static struct vkt_result g_result;

ECL_EXPORT int Install(uint64_t bridge)
{
	return chimera_vk_install((chimera_vk_bridge_fn)bridge) ? 1 : 0;
}

ECL_EXPORT int Run(void)
{
	vkt_run(chimera_vk_lookup, &g_result);
	return g_result.failed_at;
}

/* 0 the step that failed, 1 its VkResult, 2 the pixel, 3 the image's hash,
 * 4 the copied buffer's hash, 5 the bytes a second mapping gave back */
ECL_EXPORT uint64_t Value(int which)
{
	switch (which) {
	case 0: return (uint64_t)g_result.failed_at;
	case 1: return (uint64_t)(int64_t)g_result.vk_result;
	case 2: return g_result.pixel;
	case 3: return g_result.image_hash;
	case 4: return g_result.copy_hash;
	case 5: return g_result.round_trip;
	default: return 0;
	}
}

ECL_EXPORT uint64_t ContextId(void) { return chimera_vk_context_id(); }

/* For the test of a stale handle: make an instance and keep it, and later
 * ask for its devices - after the host has been told a state was loaded. */
static VkInstance g_stale;

ECL_EXPORT int MakeInstance(void)
{
	VkInstanceCreateInfo ici = { .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO };
	return (int)((PFN_vkCreateInstance)chimera_vk_lookup("vkCreateInstance"))(&ici, NULL, &g_stale);
}

ECL_EXPORT int AskKeptInstance(void)
{
	uint32_t count = 0;
	return (int)((PFN_vkEnumeratePhysicalDevices)chimera_vk_lookup("vkEnumeratePhysicalDevices"))(g_stale, &count, NULL);
}

ECL_EXPORT uint64_t KeptInstance(void) { return (uint64_t)(uintptr_t)g_stale; }

/* The new context's own instance: the same place in the host's table as the
 * kept one had in the old context's, so only the context tells them apart. */
static VkInstance g_fresh;

ECL_EXPORT int MakeFreshInstance(void)
{
	VkInstanceCreateInfo ici = { .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO };
	return (int)((PFN_vkCreateInstance)chimera_vk_lookup("vkCreateInstance"))(&ici, NULL, &g_fresh);
}

ECL_EXPORT int AskFreshInstance(void)
{
	uint32_t count = 0;
	return (int)((PFN_vkEnumeratePhysicalDevices)chimera_vk_lookup("vkEnumeratePhysicalDevices"))(g_fresh, &count, NULL);
}

ECL_EXPORT uint64_t FreshInstance(void) { return (uint64_t)(uintptr_t)g_fresh; }

ECL_EXPORT void DestroyFreshInstance(void)
{
	((PFN_vkDestroyInstance)chimera_vk_lookup("vkDestroyInstance"))(g_fresh, NULL);
}
