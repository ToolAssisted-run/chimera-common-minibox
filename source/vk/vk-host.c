/* The host half of the Vulkan bridge: the table of handles, the mapped-memory
 * copies, the choice of device, and the commands that are policy rather than
 * plumbing. The plumbing is generated (vk-bridge-host.inc) and included in
 * the middle of this file. See vk-bridge.h. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L     /* clock_gettime, under -std=c11 */
#endif
#include "vk-host.h"
#include "vk-bridge.h"
#include "vk-bridge-ops.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#endif

/* ---------------------------------------------------------------------------
 * The loader. Found at run time: nothing here links against Vulkan, so a
 * machine without it runs everything else. */

static PFN_vkGetInstanceProcAddr s_gipa;
#ifdef _WIN32
static HMODULE s_lib;
#else
static void *s_lib;
#endif

/* ---------------------------------------------------------------------------
 * One call's scratch memory. Whatever must be copied to be translated is
 * copied here and forgotten when the next call begins. */

static _Alignas(16) uint8_t s_arena[256 * 1024];
static size_t s_arena_used;
struct spill { struct spill *next; };
static struct spill *s_spills;

static int vkb_bad;     /* this call named a handle that is nothing */

static void vkb_begin(void)
{
	s_arena_used = 0;
	vkb_bad = 0;
	while (s_spills) {
		struct spill *next = s_spills->next;
		free(s_spills);
		s_spills = next;
	}
}

static void *vkb_alloc(size_t size)
{
	if (size == 0)
		return NULL;
	size = (size + 15) & ~(size_t)15;
	if (size <= sizeof s_arena - s_arena_used) {
		void *p = s_arena + s_arena_used;
		s_arena_used += size;
		memset(p, 0, size);
		return p;
	}
	struct spill *s = calloc(1, sizeof *s + 16 + size);
	if (!s) {
		vkb_bad = 1;
		return NULL;
	}
	s->next = s_spills;
	s_spills = s;
	return (uint8_t *)s + 16;
}

static void *vkb_copy(const void *from, size_t size)
{
	if (!from || size == 0)
		return NULL;
	void *p = vkb_alloc(size);
	if (p)
		memcpy(p, from, size);
	return p;
}

/* ---------------------------------------------------------------------------
 * The table. A guest's handle is (context ordinal << 32) | index; index 0 is
 * VK_NULL_HANDLE. An index is never used twice in a context, so a handle the
 * guest still holds after destroying the object names nothing rather than
 * whatever came next. */

struct memory_state {
	VkDeviceSize size;          /* of the allocation */
	void *host;                 /* the driver's mapping, or NULL */
	VkDeviceSize map_offset, map_size;
	void *shadow;               /* the guest's buffer for it, or NULL */
};

struct entry {
	uint64_t host;              /* 0 once destroyed */
	struct memory_state *memory;  /* for a VkDeviceMemory */
	uint32_t parent;            /* the pool a set or a command buffer dies with */
	uint8_t kind;
	uint8_t secondary;          /* a secondary command buffer */
};

static struct entry *s_entries;     /* [0] unused */
static uint32_t s_entry_count = 1, s_entry_room;
static uint32_t s_ordinal = 1;      /* which context of this process */
static uint64_t s_context_id;       /* what a guest is told: differs in every process too */

static uint64_t vkb_register(int kind, uint64_t host, uint32_t parent)
{
	if (!host)
		return 0;
	if (s_entry_count >= s_entry_room) {
		const uint32_t room = s_entry_room ? s_entry_room * 2 : 1024;
		struct entry *grown = realloc(s_entries, (size_t)room * sizeof *grown);
		if (!grown)
			return 0;
		if (!s_entries)
			memset(grown, 0, sizeof *grown);
		s_entries = grown;
		s_entry_room = room;
	}
	struct entry *e = &s_entries[s_entry_count];
	memset(e, 0, sizeof *e);
	e->host = host;
	e->kind = (uint8_t)kind;
	e->parent = parent;
	return ((uint64_t)s_ordinal << 32) | s_entry_count++;
}

static struct entry *vkb_entry(uint64_t id, int kind)
{
	const uint32_t index = (uint32_t)id;
#ifdef VKB_TEST_BREAK_STALE    /* a test build: a handle of any context is taken */
	if (index == 0 || index >= s_entry_count)
		return NULL;
#else
	if ((id >> 32) != s_ordinal || index == 0 || index >= s_entry_count)
		return NULL;
#endif
	struct entry *e = &s_entries[index];
	return (e->host && e->kind == kind) ? e : NULL;
}

static uint64_t vkb_new(int kind, uint64_t host) { return vkb_register(kind, host, 0); }

/* For what a driver hands out again and again - a physical device, a queue -
 * the guest must get the same handle again and again. */
static uint64_t vkb_intern(int kind, uint64_t host)
{
	for (uint32_t i = 1; i < s_entry_count; i++)
		if (s_entries[i].host == host && s_entries[i].kind == kind)
			return ((uint64_t)s_ordinal << 32) | i;
	return vkb_register(kind, host, 0);
}

static uint64_t vkb_h(uint64_t id, int kind)
{
	struct entry *e = vkb_entry(id, kind);
	if (!e) {
		vkb_bad = 1;
		return 0;
	}
	return e->host;
}

static uint64_t vkb_h0(uint64_t id, int kind) { return id ? vkb_h(id, kind) : 0; }

/* A member that is only sometimes meaningful and may hold anything when it
 * is not: something that names nothing is passed as nothing, not refused. */
static uint64_t vkb_h_soft(uint64_t id, int kind)
{
	struct entry *e = vkb_entry(id, kind);
	return e ? e->host : 0;
}

static void *vkb_h_array(const void *ids, uint64_t count, int kind)
{
	if (!ids || count == 0)
		return NULL;
	uint64_t *out = vkb_alloc((size_t)count * sizeof *out);
	for (uint64_t i = 0; out && i < count; i++)
		out[i] = vkb_h0(((const uint64_t *)ids)[i], kind);
	return out;
}

static void vkb_forget(uint64_t id, int kind)
{
	struct entry *e = vkb_entry(id, kind);
	if (!e)
		return;
	free(e->memory);
	e->memory = NULL;
	e->host = 0;
}

static void vkb_forget_children(uint32_t parent)
{
	for (uint32_t i = 1; i < s_entry_count; i++)
		if (s_entries[i].parent == parent && s_entries[i].host)
			s_entries[i].host = 0;
}

static unsigned long s_refused;
static long s_last_refused = -1;

static uint64_t vkb_refuse(uint64_t op, uint64_t value)
{
	s_refused++;
	s_last_refused = (long)op;
	return value;
}

/* ---------------------------------------------------------------------------
 * What a descriptor write's three arrays mean: only the one its type names
 * is to be read, and the other two may be anything. */

static int vkb_desc_uses_image(VkDescriptorType t)
{
	return t == VK_DESCRIPTOR_TYPE_SAMPLER || t == VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER ||
	       t == VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE || t == VK_DESCRIPTOR_TYPE_STORAGE_IMAGE ||
	       t == VK_DESCRIPTOR_TYPE_INPUT_ATTACHMENT;
}

static int vkb_desc_uses_buffer(VkDescriptorType t)
{
	return t == VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER || t == VK_DESCRIPTOR_TYPE_STORAGE_BUFFER ||
	       t == VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC || t == VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC;
}

static int vkb_desc_uses_view(VkDescriptorType t)
{
	return t == VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER || t == VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER;
}

static const void *vkb_chain(const void *first);

#include "vk-bridge-host.inc"

/* ---------------------------------------------------------------------------
 * A chain of extending structures. Each one the registry knows is copied, so
 * that it can be linked to the copy before it, and translated if it holds a
 * handle. One it does not know cannot be copied - its size is not known - and
 * is left out, which is what a driver that does not know it would do. */

static int s_chain_sorted;
static unsigned long s_chain_dropped;

static int chain_compare(const void *a, const void *b)
{
	const VkStructureType x = ((const struct vkb_chain_entry *)a)->type;
	const VkStructureType y = ((const struct vkb_chain_entry *)b)->type;
	return (x > y) - (x < y);
}

static const void *vkb_chain(const void *first)
{
	const size_t n = sizeof vkb_chain_table / sizeof vkb_chain_table[0];
	if (!s_chain_sorted) {
		qsort(vkb_chain_table, n, sizeof vkb_chain_table[0], chain_compare);
		s_chain_sorted = 1;
	}
	VkBaseOutStructure *head = NULL, *tail = NULL;
	for (const VkBaseInStructure *in = first; in; in = in->pNext) {
		struct vkb_chain_entry key = { in->sType, 0, NULL };
		const struct vkb_chain_entry *known = bsearch(&key, vkb_chain_table, n, sizeof key, chain_compare);
		if (!known) {
			s_chain_dropped++;
			continue;
		}
		VkBaseOutStructure *copy = vkb_copy(in, known->size);
		if (!copy)
			break;
		copy->pNext = NULL;
		if (known->x)
			known->x(copy);     /* translates its handles, and its own chain is this one */
		copy->pNext = NULL;
		if (tail)
			tail->pNext = copy;
		else
			head = copy;
		tail = copy;
	}
	return head;
}

/* ---------------------------------------------------------------------------
 * The context: one instance, one physical device, one device. */

static VkInstance s_instance;
static VkPhysicalDevice s_physical;
static VkDevice s_device;
static char s_description[256];

/* What may be asked of the instance and of the device. Everything else a
 * driver offers is not offered here: an extension is commands and structures
 * this bridge would have to know. */
static const char *const kInstanceExtensions[] = {
	"VK_KHR_get_physical_device_properties2",
};
static const char *const kDeviceExtensions[] = {
	"VK_KHR_maintenance1", "VK_KHR_maintenance2", "VK_KHR_maintenance3", "VK_KHR_maintenance4",
	"VK_KHR_get_memory_requirements2", "VK_KHR_bind_memory2", "VK_KHR_dedicated_allocation",
	"VK_KHR_image_format_list", "VK_KHR_sampler_mirror_clamp_to_edge", "VK_KHR_shader_float_controls",
	"VK_KHR_spirv_1_4", "VK_KHR_storage_buffer_storage_class", "VK_KHR_driver_properties",
	"VK_KHR_create_renderpass2", "VK_KHR_depth_stencil_resolve", "VK_KHR_separate_depth_stencil_layouts",
	"VK_KHR_imageless_framebuffer", "VK_KHR_uniform_buffer_standard_layout",
	"VK_KHR_shader_draw_parameters", "VK_KHR_16bit_storage", "VK_KHR_8bit_storage",
	"VK_KHR_relaxed_block_layout", "VK_KHR_variable_pointers", "VK_KHR_multiview",
	"VK_KHR_sampler_ycbcr_conversion", "VK_KHR_synchronization2", "VK_KHR_dynamic_rendering",
	"VK_KHR_copy_commands2", "VK_KHR_format_feature_flags2", "VK_KHR_zero_initialize_workgroup_memory",
	"VK_KHR_shader_terminate_invocation", "VK_KHR_shader_integer_dot_product",
	"VK_EXT_host_query_reset", "VK_EXT_shader_stencil_export", "VK_EXT_conditional_rendering",
	"VK_EXT_fragment_shader_interlock", "VK_EXT_memory_budget", "VK_EXT_4444_formats",
	"VK_EXT_custom_border_color", "VK_EXT_depth_clip_enable", "VK_EXT_depth_clip_control",
	"VK_EXT_sampler_filter_minmax", "VK_EXT_scalar_block_layout", "VK_EXT_texture_compression_astc_hdr",
	"VK_EXT_shader_demote_to_helper_invocation", "VK_EXT_non_seamless_cube_map",
	"VK_EXT_extended_dynamic_state", "VK_EXT_extended_dynamic_state2", "VK_EXT_inline_uniform_block",
	"VK_EXT_subgroup_size_control", "VK_EXT_texel_buffer_alignment", "VK_EXT_tooling_info",
	"VK_EXT_private_data", "VK_EXT_pipeline_creation_cache_control", "VK_EXT_image_robustness",
	"VK_EXT_shader_viewport_index_layer", "VK_EXT_separate_stencil_usage", "VK_EXT_descriptor_indexing",
	"VK_EXT_post_depth_coverage", "VK_EXT_provoking_vertex", "VK_EXT_line_rasterization",
	"VK_EXT_index_type_uint8", "VK_EXT_robustness2", "VK_EXT_depth_range_unrestricted",
	"VK_EXT_border_color_swizzle", "VK_EXT_rgba10x6_formats", "VK_EXT_ycbcr_2plane_444_formats",
	"VK_IMG_filter_cubic", "VK_EXT_filter_cubic",
};

static int allowed(const char *name, const char *const *list, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (strcmp(name, list[i]) == 0)
			return 1;
	return 0;
}
#define ALLOWED_INSTANCE(name) allowed(name, kInstanceExtensions, sizeof kInstanceExtensions / sizeof *kInstanceExtensions)
#define ALLOWED_DEVICE(name) allowed(name, kDeviceExtensions, sizeof kDeviceExtensions / sizeof *kDeviceExtensions)

static void load_functions(int device_level)
{
	PFN_vkGetDeviceProcAddr gdpa = NULL;
	if (device_level && s_instance)
		gdpa = (PFN_vkGetDeviceProcAddr)s_gipa(s_instance, "vkGetDeviceProcAddr");
	for (size_t i = 0; i < sizeof vkb_fn_names / sizeof vkb_fn_names[0]; i++) {
		void **slot = (void **)((char *)&vkb_fn + vkb_fn_names[i].offset);
		PFN_vkVoidFunction fn = NULL;
		if (device_level) {
			if (!vkb_fn_names[i].device)
				continue;
			if (gdpa && s_device)
				fn = gdpa(s_device, vkb_fn_names[i].name);
		} else {
			fn = s_gipa(s_instance, vkb_fn_names[i].name);
		}
		*slot = (void *)fn;
	}
}

/* Answer an enumeration of extension properties from a filtered list, by the
 * two-call rule every such command has. */
static uint64_t answer_extensions(const VkExtensionProperties *have, uint32_t have_count,
                                  const char *const *list, size_t list_count,
                                  uint32_t *pCount, VkExtensionProperties *pProperties)
{
	uint32_t n = 0;
	VkResult r = VK_SUCCESS;
	for (uint32_t i = 0; i < have_count; i++) {
		if (!allowed(have[i].extensionName, list, list_count))
			continue;
		if (pProperties) {
			if (n < *pCount)
				pProperties[n] = have[i];
			else
				r = VK_INCOMPLETE;
		}
		n++;
	}
	if (!pProperties || n < *pCount)
		*pCount = n;
	return (uint64_t)(int64_t)r;
}

static uint64_t vkb_special_vkEnumerateInstanceExtensionProperties(uint64_t op, struct vkb_vkEnumerateInstanceExtensionProperties_args *a)
{
	PFN_vkEnumerateInstanceExtensionProperties fn =
		(PFN_vkEnumerateInstanceExtensionProperties)s_gipa(NULL, "vkEnumerateInstanceExtensionProperties");
	if (!fn || !a->pPropertyCount)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_INITIALIZATION_FAILED);
	uint32_t n = 0;
	VkExtensionProperties *have = NULL;
	if (!a->pLayerName && fn(NULL, &n, NULL) >= 0 && n) {
		have = calloc(n, sizeof *have);
		if (!have || fn(NULL, &n, have) < 0)
			n = 0;
	}
	const uint64_t r = answer_extensions(have, n, kInstanceExtensions,
		sizeof kInstanceExtensions / sizeof *kInstanceExtensions, a->pPropertyCount, a->pProperties);
	free(have);
	return r;
}

static uint64_t vkb_special_vkEnumerateInstanceLayerProperties(uint64_t op, struct vkb_vkEnumerateInstanceLayerProperties_args *a)
{
	(void)op;
	if (a->pPropertyCount)
		*a->pPropertyCount = 0;     /* no layer is offered */
	return VK_SUCCESS;
}

static uint64_t vkb_special_vkEnumerateDeviceLayerProperties(uint64_t op, struct vkb_vkEnumerateDeviceLayerProperties_args *a)
{
	(void)op;
	if (a->pPropertyCount)
		*a->pPropertyCount = 0;
	return VK_SUCCESS;
}

/* Which of the machine's devices. One is offered: a renderer that chose
 * between several would choose differently on the next machine. */
static VkPhysicalDevice choose_device(void)
{
	PFN_vkEnumeratePhysicalDevices enumerate =
		(PFN_vkEnumeratePhysicalDevices)s_gipa(s_instance, "vkEnumeratePhysicalDevices");
	PFN_vkGetPhysicalDeviceProperties props =
		(PFN_vkGetPhysicalDeviceProperties)s_gipa(s_instance, "vkGetPhysicalDeviceProperties");
	uint32_t n = 0;
	if (!enumerate || !props || enumerate(s_instance, &n, NULL) < 0 || n == 0)
		return VK_NULL_HANDLE;
	VkPhysicalDevice *all = calloc(n, sizeof *all);
	if (!all || enumerate(s_instance, &n, all) < 0) {
		free(all);
		return VK_NULL_HANDLE;
	}
	const char *want = getenv("CHIMERA_VK_DEVICE");
	int best = -1, best_rank = -1;
	for (uint32_t i = 0; i < n; i++) {
		VkPhysicalDeviceProperties p;
		props(all[i], &p);
		int rank = p.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU ? 3 :
		           p.deviceType == VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU ? 2 :
		           p.deviceType == VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU ? 1 : 0;
		if (want && *want)
			rank = strstr(p.deviceName, want) ? 4 : -1;
		if (rank > best_rank) {
			best = (int)i;
			best_rank = rank;
		}
	}
	VkPhysicalDevice chosen = best >= 0 ? all[best] : VK_NULL_HANDLE;
	if (chosen) {
		VkPhysicalDeviceProperties p;
		props(chosen, &p);
		snprintf(s_description, sizeof s_description, "%.180s (Vulkan %u.%u.%u, driver %u.%u.%u)", p.deviceName,
			VK_API_VERSION_MAJOR(p.apiVersion), VK_API_VERSION_MINOR(p.apiVersion), VK_API_VERSION_PATCH(p.apiVersion),
			VK_API_VERSION_MAJOR(p.driverVersion), VK_API_VERSION_MINOR(p.driverVersion),
			VK_API_VERSION_PATCH(p.driverVersion));
	}
	free(all);
	return chosen;
}

static uint64_t vkb_special_vkCreateInstance(uint64_t op, struct vkb_vkCreateInstance_args *a)
{
	PFN_vkCreateInstance create = (PFN_vkCreateInstance)s_gipa(NULL, "vkCreateInstance");
	if (!create || s_instance || !a->pCreateInfo || !a->pInstance)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_INITIALIZATION_FAILED);
	VkInstanceCreateInfo info = *a->pCreateInfo;
	info.pNext = NULL;              /* a chain here is debug messengers and direct driver loading */
	info.flags = 0;
	info.enabledLayerCount = 0;
	info.ppEnabledLayerNames = NULL;
	for (uint32_t i = 0; i < info.enabledExtensionCount; i++)
		if (!ALLOWED_INSTANCE(info.ppEnabledExtensionNames[i]))
			return (uint64_t)(int64_t)VK_ERROR_EXTENSION_NOT_PRESENT;
	VkInstance instance = VK_NULL_HANDLE;
	const VkResult r = create(&info, NULL, &instance);
	if (r < 0)
		return (uint64_t)(int64_t)r;
	s_instance = instance;
	load_functions(0);
	s_physical = choose_device();
	if (!s_physical) {
		vkb_fn.vkDestroyInstance(s_instance, NULL);
		s_instance = VK_NULL_HANDLE;
		return (uint64_t)(int64_t)VK_ERROR_INITIALIZATION_FAILED;
	}
	*a->pInstance = (VkInstance)vkb_new(VKB_K_Instance, (uint64_t)(uintptr_t)instance);
	return (uint64_t)(int64_t)r;
}

static uint64_t vkb_special_vkEnumeratePhysicalDevices(uint64_t op, struct vkb_vkEnumeratePhysicalDevices_args *a)
{
	if (!vkb_entry((uint64_t)(uintptr_t)a->instance, VKB_K_Instance) || !a->pPhysicalDeviceCount)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_DEVICE_LOST);
	if (!a->pPhysicalDevices) {
		*a->pPhysicalDeviceCount = 1;
		return VK_SUCCESS;
	}
	if (*a->pPhysicalDeviceCount == 0)
		return (uint64_t)(int64_t)VK_INCOMPLETE;
	a->pPhysicalDevices[0] = (VkPhysicalDevice)vkb_intern(VKB_K_PhysicalDevice, (uint64_t)(uintptr_t)s_physical);
	*a->pPhysicalDeviceCount = 1;
	return VK_SUCCESS;
}

static uint64_t vkb_special_vkEnumerateDeviceExtensionProperties(uint64_t op, struct vkb_vkEnumerateDeviceExtensionProperties_args *a)
{
	const VkPhysicalDevice phys = (VkPhysicalDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->physicalDevice, VKB_K_PhysicalDevice);
	if (vkb_bad || !vkb_fn.vkEnumerateDeviceExtensionProperties || !a->pPropertyCount)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_DEVICE_LOST);
	uint32_t n = 0;
	VkExtensionProperties *have = NULL;
	if (!a->pLayerName && vkb_fn.vkEnumerateDeviceExtensionProperties(phys, NULL, &n, NULL) >= 0 && n) {
		have = calloc(n, sizeof *have);
		if (!have || vkb_fn.vkEnumerateDeviceExtensionProperties(phys, NULL, &n, have) < 0)
			n = 0;
	}
	const uint64_t r = answer_extensions(have, n, kDeviceExtensions,
		sizeof kDeviceExtensions / sizeof *kDeviceExtensions, a->pPropertyCount, a->pProperties);
	free(have);
	return r;
}

static uint64_t vkb_special_vkCreateDevice(uint64_t op, struct vkb_vkCreateDevice_args *a)
{
	const VkPhysicalDevice phys = (VkPhysicalDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->physicalDevice, VKB_K_PhysicalDevice);
	if (vkb_bad || s_device || !a->pCreateInfo || !a->pDevice || !vkb_fn.vkCreateDevice)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_INITIALIZATION_FAILED);
	VkDeviceCreateInfo info = *a->pCreateInfo;
	vkb_x_VkDeviceCreateInfo(&info);
	info.enabledLayerCount = 0;
	info.ppEnabledLayerNames = NULL;
	for (uint32_t i = 0; i < info.enabledExtensionCount; i++)
		if (!ALLOWED_DEVICE(info.ppEnabledExtensionNames[i]))
			return (uint64_t)(int64_t)VK_ERROR_EXTENSION_NOT_PRESENT;
	if (vkb_bad)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_INITIALIZATION_FAILED);
	VkDevice device = VK_NULL_HANDLE;
	const VkResult r = vkb_fn.vkCreateDevice(phys, &info, NULL, &device);
	if (r < 0)
		return (uint64_t)(int64_t)r;
	s_device = device;
	load_functions(1);
	*a->pDevice = (VkDevice)vkb_new(VKB_K_Device, (uint64_t)(uintptr_t)device);
	return (uint64_t)(int64_t)r;
}

/* ---- memory: no type is coherent, and a mapping is the guest's buffer ---- */

static void hide_coherence(VkPhysicalDeviceMemoryProperties *p)
{
	for (uint32_t i = 0; i < p->memoryTypeCount; i++)
		p->memoryTypes[i].propertyFlags &= ~(VkMemoryPropertyFlags)VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
}

static uint64_t vkb_special_vkGetPhysicalDeviceMemoryProperties(uint64_t op, struct vkb_vkGetPhysicalDeviceMemoryProperties_args *a)
{
	const VkPhysicalDevice phys = (VkPhysicalDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->physicalDevice, VKB_K_PhysicalDevice);
	if (vkb_bad || !vkb_fn.vkGetPhysicalDeviceMemoryProperties || !a->pMemoryProperties)
		return vkb_refuse(op, 0);
	vkb_fn.vkGetPhysicalDeviceMemoryProperties(phys, a->pMemoryProperties);
	hide_coherence(a->pMemoryProperties);
	return 0;
}

static uint64_t vkb_special_vkGetPhysicalDeviceMemoryProperties2(uint64_t op, struct vkb_vkGetPhysicalDeviceMemoryProperties2_args *a)
{
	const VkPhysicalDevice phys = (VkPhysicalDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->physicalDevice, VKB_K_PhysicalDevice);
	PFN_vkGetPhysicalDeviceMemoryProperties2 fn = vkb_fn.vkGetPhysicalDeviceMemoryProperties2;
#ifdef VK_OP_vkGetPhysicalDeviceMemoryProperties2KHR
	if (op == VK_OP_vkGetPhysicalDeviceMemoryProperties2KHR || !fn)
		fn = vkb_fn.vkGetPhysicalDeviceMemoryProperties2KHR;
#endif
	if (vkb_bad || !fn || !a->pMemoryProperties)
		return vkb_refuse(op, 0);
	fn(phys, a->pMemoryProperties);
	hide_coherence(&a->pMemoryProperties->memoryProperties);
	return 0;
}

static uint64_t vkb_special_vkAllocateMemory(uint64_t op, struct vkb_vkAllocateMemory_args *a)
{
	const VkDevice device = (VkDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->device, VKB_K_Device);
	if (vkb_bad || !a->pAllocateInfo || !a->pMemory || !vkb_fn.vkAllocateMemory)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_DEVICE_LOST);
	VkMemoryAllocateInfo info = *a->pAllocateInfo;
	vkb_x_VkMemoryAllocateInfo(&info);
	if (vkb_bad)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_DEVICE_LOST);
	struct memory_state *state = calloc(1, sizeof *state);
	if (!state)
		return (uint64_t)(int64_t)VK_ERROR_OUT_OF_HOST_MEMORY;
	VkDeviceMemory memory = VK_NULL_HANDLE;
	const VkResult r = vkb_fn.vkAllocateMemory(device, &info, NULL, &memory);
	if (r < 0) {
		free(state);
		return (uint64_t)(int64_t)r;
	}
	state->size = info.allocationSize;
	const uint64_t id = vkb_new(VKB_K_DeviceMemory, (uint64_t)memory);
	struct entry *e = vkb_entry(id, VKB_K_DeviceMemory);
	if (!e) {
		vkb_fn.vkFreeMemory(device, memory, NULL);
		free(state);
		return (uint64_t)(int64_t)VK_ERROR_OUT_OF_HOST_MEMORY;
	}
	e->memory = state;
	*a->pMemory = (VkDeviceMemory)id;
	return (uint64_t)(int64_t)r;
}

static uint64_t vkb_special_vkFreeMemory(uint64_t op, struct vkb_vkFreeMemory_args *a)
{
	const VkDevice device = (VkDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->device, VKB_K_Device);
	if (!a->memory)
		return 0;
	struct entry *e = vkb_entry((uint64_t)a->memory, VKB_K_DeviceMemory);
	if (vkb_bad || !e || !vkb_fn.vkFreeMemory)
		return vkb_refuse(op, 0);
	vkb_fn.vkFreeMemory(device, (VkDeviceMemory)e->host, NULL);     /* which unmaps */
	vkb_forget((uint64_t)a->memory, VKB_K_DeviceMemory);
	return 0;
}

static uint64_t vkb_special_vkMapMemory(uint64_t op, struct vkb_vkMapMemory_args *a)
{
	const VkDevice device = (VkDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->device, VKB_K_Device);
	struct entry *e = vkb_entry((uint64_t)a->memory, VKB_K_DeviceMemory);
	if (vkb_bad || !e || !e->memory || !a->ppData || !vkb_fn.vkMapMemory)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_DEVICE_LOST);
	struct memory_state *m = e->memory;
	if (m->host || a->offset >= m->size)
		return (uint64_t)(int64_t)VK_ERROR_MEMORY_MAP_FAILED;
	const VkDeviceSize size = a->size == VK_WHOLE_SIZE ? m->size - a->offset : a->size;
	if (size > m->size - a->offset)
		return (uint64_t)(int64_t)VK_ERROR_MEMORY_MAP_FAILED;
	void *host = NULL;
	const VkResult r = vkb_fn.vkMapMemory(device, (VkDeviceMemory)e->host, a->offset, size, a->flags, &host);
	if (r < 0)
		return (uint64_t)(int64_t)r;
	m->host = host;
	m->map_offset = a->offset;
	m->map_size = size;
	m->shadow = NULL;
	*(uint64_t *)a->ppData = size;      /* the length, where a driver puts its pointer */
	return (uint64_t)(int64_t)r;
}

static uint64_t map_attach(struct vkb_map_attach_args *a)
{
	struct entry *e = vkb_entry(a->memory, VKB_K_DeviceMemory);
	if (!e || !e->memory || !e->memory->host || !a->shadow)
		return vkb_refuse(VKB_OP_MAP_ATTACH, 0);
	e->memory->shadow = (void *)(uintptr_t)a->shadow;
	memcpy(e->memory->shadow, e->memory->host, (size_t)e->memory->map_size);
	return 1;
}

static uint64_t vkb_special_vkUnmapMemory(uint64_t op, struct vkb_vkUnmapMemory_args *a)
{
	const VkDevice device = (VkDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->device, VKB_K_Device);
	struct entry *e = vkb_entry((uint64_t)a->memory, VKB_K_DeviceMemory);
	if (vkb_bad || !e || !e->memory || !e->memory->host || !vkb_fn.vkUnmapMemory)
		return vkb_refuse(op, 0);
	struct memory_state *m = e->memory;
	/* Nothing is written out here. Unmapping does not flush - and writing
	 * the guest's buffer out would put bytes it never touched over what the
	 * device wrote since it last read them back. */
	vkb_fn.vkUnmapMemory(device, (VkDeviceMemory)e->host);
	m->host = NULL;
	m->shadow = NULL;
	return 0;
}

/* The bytes of one range, guest to driver (out) or driver to guest. */
static void copy_range(const VkMappedMemoryRange *range, int out)
{
	struct entry *e = vkb_entry((uint64_t)range->memory, VKB_K_DeviceMemory);
	if (!e || !e->memory || !e->memory->host || !e->memory->shadow)
		return;
	const struct memory_state *m = e->memory;
	VkDeviceSize from = range->offset, to = range->size == VK_WHOLE_SIZE ? m->map_offset + m->map_size
	                                                                    : range->offset + range->size;
	if (from < m->map_offset)
		from = m->map_offset;
	if (to > m->map_offset + m->map_size)
		to = m->map_offset + m->map_size;
	if (from >= to)
		return;
	uint8_t *host = (uint8_t *)m->host + (from - m->map_offset);
	uint8_t *shadow = (uint8_t *)m->shadow + (from - m->map_offset);
	if (out)
		memcpy(host, shadow, (size_t)(to - from));
	else
		memcpy(shadow, host, (size_t)(to - from));
}

static uint64_t vkb_special_vkFlushMappedMemoryRanges(uint64_t op, struct vkb_vkFlushMappedMemoryRanges_args *a)
{
	const VkDevice device = (VkDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->device, VKB_K_Device);
	VkMappedMemoryRange *ranges = vkb_copy(a->pMemoryRanges, (size_t)a->memoryRangeCount * sizeof *ranges);
	for (uint32_t i = 0; ranges && i < a->memoryRangeCount; i++) {
#ifndef VKB_TEST_BREAK_FLUSH    /* a test build: a flush writes nothing out */
		copy_range(&a->pMemoryRanges[i], 1);
#endif
		vkb_x_VkMappedMemoryRange(&ranges[i]);
	}
	if (vkb_bad || !vkb_fn.vkFlushMappedMemoryRanges)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_DEVICE_LOST);
	return (uint64_t)(int64_t)vkb_fn.vkFlushMappedMemoryRanges(device, a->memoryRangeCount, ranges);
}

static uint64_t vkb_special_vkInvalidateMappedMemoryRanges(uint64_t op, struct vkb_vkInvalidateMappedMemoryRanges_args *a)
{
	const VkDevice device = (VkDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->device, VKB_K_Device);
	VkMappedMemoryRange *ranges = vkb_copy(a->pMemoryRanges, (size_t)a->memoryRangeCount * sizeof *ranges);
	for (uint32_t i = 0; ranges && i < a->memoryRangeCount; i++)
		vkb_x_VkMappedMemoryRange(&ranges[i]);
	if (vkb_bad || !vkb_fn.vkInvalidateMappedMemoryRanges)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_DEVICE_LOST);
	const VkResult r = vkb_fn.vkInvalidateMappedMemoryRanges(device, a->memoryRangeCount, ranges);
#ifndef VKB_TEST_BREAK_INVALIDATE    /* a test build: an invalidate reads nothing back */
	for (uint32_t i = 0; r >= 0 && i < a->memoryRangeCount; i++)
		copy_range(&a->pMemoryRanges[i], 0);
#endif
	return (uint64_t)(int64_t)r;
}

/* ---- what dies with a pool ------------------------------------------------ */

static uint64_t vkb_special_vkAllocateCommandBuffers(uint64_t op, struct vkb_vkAllocateCommandBuffers_args *a)
{
	const VkDevice device = (VkDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->device, VKB_K_Device);
	if (!a->pAllocateInfo || !a->pCommandBuffers || !vkb_fn.vkAllocateCommandBuffers)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_DEVICE_LOST);
	VkCommandBufferAllocateInfo info = *a->pAllocateInfo;
	const uint32_t pool = (uint32_t)(uint64_t)info.commandPool;
	vkb_x_VkCommandBufferAllocateInfo(&info);
	VkCommandBuffer *out = vkb_alloc((size_t)info.commandBufferCount * sizeof *out);
	if (vkb_bad || !out)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_DEVICE_LOST);
	const VkResult r = vkb_fn.vkAllocateCommandBuffers(device, &info, out);
	for (uint32_t i = 0; r >= 0 && i < info.commandBufferCount; i++) {
		const uint64_t id = vkb_register(VKB_K_CommandBuffer, (uint64_t)(uintptr_t)out[i], pool);
		struct entry *e = vkb_entry(id, VKB_K_CommandBuffer);
		if (e)
			e->secondary = info.level == VK_COMMAND_BUFFER_LEVEL_SECONDARY;
		a->pCommandBuffers[i] = (VkCommandBuffer)id;
	}
	return (uint64_t)(int64_t)r;
}

static uint64_t vkb_special_vkAllocateDescriptorSets(uint64_t op, struct vkb_vkAllocateDescriptorSets_args *a)
{
	const VkDevice device = (VkDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->device, VKB_K_Device);
	if (!a->pAllocateInfo || !a->pDescriptorSets || !vkb_fn.vkAllocateDescriptorSets)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_DEVICE_LOST);
	VkDescriptorSetAllocateInfo info = *a->pAllocateInfo;
	const uint32_t pool = (uint32_t)(uint64_t)info.descriptorPool;
	vkb_x_VkDescriptorSetAllocateInfo(&info);
	VkDescriptorSet *out = vkb_alloc((size_t)info.descriptorSetCount * sizeof *out);
	if (vkb_bad || !out)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_DEVICE_LOST);
	const VkResult r = vkb_fn.vkAllocateDescriptorSets(device, &info, out);
	for (uint32_t i = 0; r >= 0 && i < info.descriptorSetCount; i++)
		a->pDescriptorSets[i] = (VkDescriptorSet)vkb_register(VKB_K_DescriptorSet, (uint64_t)out[i], pool);
	return (uint64_t)(int64_t)r;
}

static uint64_t vkb_special_vkDestroyCommandPool(uint64_t op, struct vkb_vkDestroyCommandPool_args *a)
{
	const VkDevice device = (VkDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->device, VKB_K_Device);
	const VkCommandPool pool = (VkCommandPool)vkb_h0((uint64_t)a->commandPool, VKB_K_CommandPool);
	if (vkb_bad || !vkb_fn.vkDestroyCommandPool)
		return vkb_refuse(op, 0);
	vkb_fn.vkDestroyCommandPool(device, pool, NULL);
	if (pool) {
		vkb_forget_children((uint32_t)(uint64_t)a->commandPool);
		vkb_forget((uint64_t)a->commandPool, VKB_K_CommandPool);
	}
	return 0;
}

static uint64_t vkb_special_vkDestroyDescriptorPool(uint64_t op, struct vkb_vkDestroyDescriptorPool_args *a)
{
	const VkDevice device = (VkDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->device, VKB_K_Device);
	const VkDescriptorPool pool = (VkDescriptorPool)vkb_h0((uint64_t)a->descriptorPool, VKB_K_DescriptorPool);
	if (vkb_bad || !vkb_fn.vkDestroyDescriptorPool)
		return vkb_refuse(op, 0);
	vkb_fn.vkDestroyDescriptorPool(device, pool, NULL);
	if (pool) {
		vkb_forget_children((uint32_t)(uint64_t)a->descriptorPool);
		vkb_forget((uint64_t)a->descriptorPool, VKB_K_DescriptorPool);
	}
	return 0;
}

static uint64_t vkb_special_vkResetDescriptorPool(uint64_t op, struct vkb_vkResetDescriptorPool_args *a)
{
	const VkDevice device = (VkDevice)(uintptr_t)vkb_h((uint64_t)(uintptr_t)a->device, VKB_K_Device);
	const VkDescriptorPool pool = (VkDescriptorPool)vkb_h((uint64_t)a->descriptorPool, VKB_K_DescriptorPool);
	if (vkb_bad || !vkb_fn.vkResetDescriptorPool)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_DEVICE_LOST);
	const VkResult r = vkb_fn.vkResetDescriptorPool(device, pool, a->flags);
	vkb_forget_children((uint32_t)(uint64_t)a->descriptorPool);
	return (uint64_t)(int64_t)r;
}

/* A primary command buffer's inheritance info is ignored, and so may point
 * anywhere. It is followed only for a secondary one. */
static uint64_t vkb_special_vkBeginCommandBuffer(uint64_t op, struct vkb_vkBeginCommandBuffer_args *a)
{
	struct entry *e = vkb_entry((uint64_t)(uintptr_t)a->commandBuffer, VKB_K_CommandBuffer);
	if (!e || !a->pBeginInfo || !vkb_fn.vkBeginCommandBuffer)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_DEVICE_LOST);
	VkCommandBufferBeginInfo info = *a->pBeginInfo;
	if (!e->secondary)
		info.pInheritanceInfo = NULL;
	vkb_x_VkCommandBufferBeginInfo(&info);
	if (vkb_bad)
		return vkb_refuse(op, (uint64_t)(int64_t)VK_ERROR_DEVICE_LOST);
	return (uint64_t)(int64_t)vkb_fn.vkBeginCommandBuffer((VkCommandBuffer)(uintptr_t)e->host, &info);
}

/* ---- the end of a device, an instance, a context -------------------------- */

/* Destroy what the table still holds, newest first: what was made later may
 * depend on what was made earlier, never the other way. */
static void destroy_objects(void)
{
	if (!s_device)
		return;
	if (vkb_fn.vkDeviceWaitIdle)
		vkb_fn.vkDeviceWaitIdle(s_device);
	for (uint32_t i = s_entry_count; i-- > 1;) {
		struct entry *e = &s_entries[i];
		const uint64_t h = e->host;
		if (!h || e->parent)        /* what a pool owns goes with the pool */
			continue;
#define DESTROY(Kind, fn, Type) \
	case VKB_K_##Kind: if (vkb_fn.fn) vkb_fn.fn(s_device, (Type)h, NULL); break;
		switch (e->kind) {
		DESTROY(Buffer, vkDestroyBuffer, VkBuffer)
		DESTROY(BufferView, vkDestroyBufferView, VkBufferView)
		DESTROY(Image, vkDestroyImage, VkImage)
		DESTROY(ImageView, vkDestroyImageView, VkImageView)
		DESTROY(ShaderModule, vkDestroyShaderModule, VkShaderModule)
		DESTROY(Pipeline, vkDestroyPipeline, VkPipeline)
		DESTROY(PipelineCache, vkDestroyPipelineCache, VkPipelineCache)
		DESTROY(PipelineLayout, vkDestroyPipelineLayout, VkPipelineLayout)
		DESTROY(RenderPass, vkDestroyRenderPass, VkRenderPass)
		DESTROY(Framebuffer, vkDestroyFramebuffer, VkFramebuffer)
		DESTROY(DescriptorSetLayout, vkDestroyDescriptorSetLayout, VkDescriptorSetLayout)
		DESTROY(DescriptorPool, vkDestroyDescriptorPool, VkDescriptorPool)
		DESTROY(Sampler, vkDestroySampler, VkSampler)
		DESTROY(CommandPool, vkDestroyCommandPool, VkCommandPool)
		DESTROY(Fence, vkDestroyFence, VkFence)
		DESTROY(Semaphore, vkDestroySemaphore, VkSemaphore)
		DESTROY(Event, vkDestroyEvent, VkEvent)
		DESTROY(QueryPool, vkDestroyQueryPool, VkQueryPool)
		DESTROY(DeviceMemory, vkFreeMemory, VkDeviceMemory)
		DESTROY(SamplerYcbcrConversion, vkDestroySamplerYcbcrConversion, VkSamplerYcbcrConversion)
		DESTROY(DescriptorUpdateTemplate, vkDestroyDescriptorUpdateTemplate, VkDescriptorUpdateTemplate)
		DESTROY(PrivateDataSlot, vkDestroyPrivateDataSlot, VkPrivateDataSlot)
		default: continue;      /* not the device's: an instance, a queue */
		}
#undef DESTROY
		free(e->memory);
		e->memory = NULL;
		e->host = 0;
	}
}

/* Everything of the device is gone from the table; the instance and its
 * physical device stay. */
static void forget_device_entries(void)
{
	for (uint32_t i = 1; i < s_entry_count; i++) {
		struct entry *e = &s_entries[i];
		if (e->kind == VKB_K_Instance || e->kind == VKB_K_PhysicalDevice)
			continue;
		free(e->memory);
		e->memory = NULL;
		e->host = 0;
	}
}

static uint64_t vkb_special_vkDestroyDevice(uint64_t op, struct vkb_vkDestroyDevice_args *a)
{
	if (!a->device)
		return 0;
	if (!vkb_entry((uint64_t)(uintptr_t)a->device, VKB_K_Device) || !s_device)
		return vkb_refuse(op, 0);
	destroy_objects();      /* what the guest left behind is not left to the driver */
	vkb_fn.vkDestroyDevice(s_device, NULL);
	s_device = VK_NULL_HANDLE;
	forget_device_entries();
	return 0;
}

static void destroy_context(void)
{
	if (s_device) {
		destroy_objects();
		if (vkb_fn.vkDestroyDevice)
			vkb_fn.vkDestroyDevice(s_device, NULL);
		s_device = VK_NULL_HANDLE;
	}
	if (s_instance) {
		if (vkb_fn.vkDestroyInstance)
			vkb_fn.vkDestroyInstance(s_instance, NULL);
		s_instance = VK_NULL_HANDLE;
	}
	s_physical = VK_NULL_HANDLE;
	for (uint32_t i = 1; i < s_entry_count; i++)
		free(s_entries[i].memory);
	s_entry_count = 1;
	memset(&vkb_fn, 0, sizeof vkb_fn);
}

static uint64_t vkb_special_vkDestroyInstance(uint64_t op, struct vkb_vkDestroyInstance_args *a)
{
	if (!a->instance)
		return 0;
	if (!vkb_entry((uint64_t)(uintptr_t)a->instance, VKB_K_Instance))
		return vkb_refuse(op, 0);
	destroy_context();
	return 0;
}

/* Any two contexts differ - this process's from each other, and from any
 * other process's, because a savestate made in one is loaded in another. */
static void mint_context_id(void)
{
	static uint64_t counter;
	uint64_t x = (uint64_t)time(NULL) * 0x9E3779B97F4A7C15ull;
#ifdef _WIN32
	x ^= (uint64_t)GetCurrentProcessId() << 32;
	LARGE_INTEGER ticks;
	if (QueryPerformanceCounter(&ticks))
		x ^= (uint64_t)ticks.QuadPart;
#else
	x ^= (uint64_t)getpid() << 32;
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
		x ^= (uint64_t)ts.tv_nsec * 0xBF58476D1CE4E5B9ull;
#endif
	x += ++counter * 0x94D049BB133111EBull;
	s_context_id = x ? x : 1;
}

void chimera_vk_host_state_loaded(void)
{
	destroy_context();
	s_ordinal++;
	mint_context_id();
}

int chimera_vk_host_init(char *err, int errlen)
{
	if (s_gipa)
		return 0;
#ifdef _WIN32
	s_lib = LoadLibraryA("vulkan-1.dll");
	if (s_lib)
		s_gipa = (PFN_vkGetInstanceProcAddr)(void *)GetProcAddress(s_lib, "vkGetInstanceProcAddr");
#else
	s_lib = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
	if (s_lib)
		s_gipa = (PFN_vkGetInstanceProcAddr)dlsym(s_lib, "vkGetInstanceProcAddr");
#endif
	if (!s_gipa) {
		if (err && errlen > 0)
			snprintf(err, (size_t)errlen, "%s", s_lib ? "the Vulkan loader has no vkGetInstanceProcAddr"
			                                         : "no Vulkan loader on this machine");
		return -1;
	}
	mint_context_id();
	return 0;
}

void chimera_vk_host_shutdown(void)
{
	destroy_context();
	free(s_entries);
	s_entries = NULL;
	s_entry_room = 0;
	s_entry_count = 1;
#ifdef _WIN32
	if (s_lib)
		FreeLibrary(s_lib);
#else
	if (s_lib)
		dlclose(s_lib);
#endif
	s_lib = NULL;
	s_gipa = NULL;
}

const char *chimera_vk_host_description(void) { return s_description; }

unsigned long chimera_vk_host_refused(long *last_op)
{
	if (last_op)
		*last_op = s_last_refused;
	return s_refused;
}

uintptr_t VKB_GUEST_ABI chimera_vk_host_dispatch(uintptr_t op, uintptr_t a, uintptr_t b,
                                                 uintptr_t c, uintptr_t d, uintptr_t e)
{
	(void)b; (void)c; (void)d; (void)e;
	switch (op) {
	case VKB_OP_LIST_LENGTH:
		return VKB_LIST_LENGTH;
	case VKB_OP_CONTEXT_ID:
		return (uintptr_t)s_context_id;
	case VKB_OP_DESCRIPTION: {
		struct vkb_description_args *args = (struct vkb_description_args *)a;
		if (args && args->out && args->size)
			snprintf((char *)(uintptr_t)args->out, args->size, "%s", s_description);
		return 0;
	}
	case VKB_OP_MAP_ATTACH:
		return a ? (uintptr_t)map_attach((struct vkb_map_attach_args *)a) : 0;
	default:
		break;
	}
	if (!s_gipa || !a)
		return (uintptr_t)vkb_refuse(op, 0);
	vkb_begin();
	return (uintptr_t)vkb_dispatch_generated(op, (void *)a);
}
