/* The Vulkan bridge's test, written once and run twice: against the machine's
 * driver directly, and from inside a guest through the bridge. The same
 * commands on the same device must leave the same bytes.
 *
 * It needs no shader, so it needs no shader compiler: an image is cleared by
 * a render pass and copied out, and a buffer is written through a mapping and
 * copied to another. That is an instance, a device, memory of both kinds, a
 * mapping in each direction, a render pass, a framebuffer, command buffers, a
 * queue and a fence - every kind of handle crossing the bridge, in structures
 * and in arrays.
 *
 * Then a draw, with two shaders kept compiled (triangle-spv.h): a pipeline, a
 * descriptor set whose write carries two pointers to nothing beside the one
 * that counts, push constants, a vertex buffer and a second command buffer.
 *
 * Then the same draw with the uniform PUSHED (VK_KHR_push_descriptor) in place
 * of a descriptor set, where the device has that extension: the command is
 * found by name through the device, as a renderer's loader finds it, and its
 * write names a set that does not exist, which a pushed write may. */
#pragma once

#include <vulkan/vulkan_core.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "triangle-spv.h"

typedef void *(*vkt_lookup)(const char *name);

struct vkt_result {
	int failed_at;          /* 0, or the step that failed */
	int vk_result;          /* what it answered */
	uint32_t pixel;         /* the cleared image's first pixel */
	uint64_t image_hash;    /* every byte of it */
	uint64_t copy_hash;     /* every byte of the buffer that was written and copied */
	uint32_t round_trip;    /* bytes that came back from a second mapping as they were flushed */
	uint64_t attach_hash;   /* the buffer the device wrote, as a NEW mapping of it first shows it */
	uint32_t drawn_inside;  /* a pixel the triangle covers */
	uint32_t drawn_outside; /* one it does not */
	uint64_t drawn_hash;    /* every byte of the drawn image */
	uint32_t push_limit;    /* how many descriptors the device says may be pushed; 0 = it has no such extension */
	uint32_t pushed_inside; /* a pixel of the triangle drawn with a pushed uniform */
	uint64_t pushed_hash;   /* every byte of that image */
	uint32_t event_set;     /* 1: an event set by a command in the queue was then found set; 0: the device has no VK_KHR_synchronization2 */
	uint32_t names_present; /* bit i: vkGetDeviceProcAddr answered either name of pair i (vkt_name_pairs) */
	uint32_t templ_inside;  /* a pixel of the triangle drawn with its uniform pushed through a template; 0 = no templates */
	uint64_t templ_hash;    /* every byte of that image */
};

/* Commands with two names each, an extension's and a version's. The device
 * has one when either name answers; the bridge must say the same as the
 * driver, and answer both names alike. */
static const char *const vkt_name_pairs[][2] = {
	{"vkCmdBeginRenderingKHR", "vkCmdBeginRendering"},
	{"vkCmdSetEvent2KHR", "vkCmdSetEvent2"},
	{"vkCmdPipelineBarrier2KHR", "vkCmdPipelineBarrier2"},
	{"vkCreateRenderPass2KHR", "vkCreateRenderPass2"},
	{"vkCmdCopyBuffer2KHR", "vkCmdCopyBuffer2"},
	{"vkCmdSetCullModeEXT", "vkCmdSetCullMode"},
	{"vkTrimCommandPoolKHR", "vkTrimCommandPool"},
	/* the descriptor update templates, back in the bridge, and three
	 * commands of offered extensions that were missing from it */
	{"vkCreateDescriptorUpdateTemplateKHR", "vkCreateDescriptorUpdateTemplate"},
	{"vkUpdateDescriptorSetWithTemplateKHR", "vkUpdateDescriptorSetWithTemplate"},
	{"vkCmdPushDescriptorSetWithTemplateKHR", "vkCmdPushDescriptorSetWithTemplate"},
	{"vkCmdSetLineStippleEXT", "vkCmdSetLineStipple"},
	{"vkCmdSetPatchControlPointsEXT", "vkCmdSetPatchControlPointsEXT"},
	{"vkCmdSetLogicOpEXT", "vkCmdSetLogicOpEXT"},
};

/* What a template's data looks like here: the buffer's handle after eight
 * bytes of something else, at an offset only the template says. */
struct vkt_templ_data {
	uint64_t before;
	VkDescriptorBufferInfo info;
};

#define VKT_SIDE 64
#define VKT_BYTES (VKT_SIDE * VKT_SIDE * 4)

static uint64_t vkt_hash(const uint8_t *p, size_t n)
{
	uint64_t h = 0xcbf29ce484222325ull;
	for (size_t i = 0; i < n; i++)
		h = (h ^ p[i]) * 0x100000001b3ull;
	return h;
}

static int vkt_memory_type(const VkPhysicalDeviceMemoryProperties *props, uint32_t allowed, VkMemoryPropertyFlags want)
{
	for (uint32_t i = 0; i < props->memoryTypeCount; i++)
		if ((allowed & (1u << i)) && (props->memoryTypes[i].propertyFlags & want) == want)
			return (int)i;
	return -1;
}

#define VKT(name) ((PFN_##name)get(#name))

/* A buffer the host can see, bound and mapped. */
static VkResult vkt_buffer(vkt_lookup get, VkDevice dev, const VkPhysicalDeviceMemoryProperties *mem,
                           VkDeviceSize size, VkBufferUsageFlags usage, VkBuffer *buffer, VkDeviceMemory *memory,
                           void **mapped)
{
	VkBufferCreateInfo bci = { .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, .size = size, .usage = usage,
	                           .sharingMode = VK_SHARING_MODE_EXCLUSIVE };
	VkResult r = VKT(vkCreateBuffer)(dev, &bci, NULL, buffer);
	if (r != VK_SUCCESS)
		return r;
	VkMemoryRequirements req;
	VKT(vkGetBufferMemoryRequirements)(dev, *buffer, &req);
	const int type = vkt_memory_type(mem, req.memoryTypeBits, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT);
	if (type < 0)
		return VK_ERROR_FEATURE_NOT_PRESENT;
	VkMemoryAllocateInfo mai = { .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, .allocationSize = req.size,
	                             .memoryTypeIndex = (uint32_t)type };
	r = VKT(vkAllocateMemory)(dev, &mai, NULL, memory);
	if (r != VK_SUCCESS)
		return r;
	r = VKT(vkBindBufferMemory)(dev, *buffer, *memory, 0);
	if (r != VK_SUCCESS)
		return r;
	return VKT(vkMapMemory)(dev, *memory, 0, VK_WHOLE_SIZE, 0, mapped);
}
#define VKT_STEP(n, expr) do { r = (expr); if (r != VK_SUCCESS) { out->failed_at = (n); out->vk_result = (int)r; return; } } while (0)
#define VKT_NEED(n, cond) do { if (!(cond)) { out->failed_at = (n); out->vk_result = 0; return; } } while (0)

/* through_bridge: also do what only the bridge may be asked - what a driver
 * asked directly would die of. */
static void vkt_run(vkt_lookup get, struct vkt_result *out, int through_bridge)
{
	VkResult r;
	uint32_t count_ext = 0;
	memset(out, 0, sizeof *out);

	VkApplicationInfo app = { .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO, .pApplicationName = "vktest",
	                          .apiVersion = VK_API_VERSION_1_0 };
	VkInstanceCreateInfo ici = { .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, .pApplicationInfo = &app };
	VkInstance instance = VK_NULL_HANDLE;
	/* Asking a device what it can push needs this instance extension. */
	static const char *const props2_name = VK_KHR_GET_PHYSICAL_DEVICE_PROPERTIES_2_EXTENSION_NAME;
	static const char *const push_name = VK_KHR_PUSH_DESCRIPTOR_EXTENSION_NAME;
	static VkExtensionProperties ext[512];
	static const char *const sync2_name = VK_KHR_SYNCHRONIZATION_2_EXTENSION_NAME;
	static const char *const templ_name = VK_KHR_DESCRIPTOR_UPDATE_TEMPLATE_EXTENSION_NAME;
	static const char *const eds2_name = VK_EXT_EXTENDED_DYNAMIC_STATE_2_EXTENSION_NAME;
	static const char *const line_name = VK_EXT_LINE_RASTERIZATION_EXTENSION_NAME;
	int has_props2 = 0, has_push = 0, has_sync2 = 0, has_templ = 0, has_eds2 = 0, has_line = 0;
	const char *dev_ext[7];
	uint32_t dev_ext_count = 0;
	count_ext = 512;
	r = VKT(vkEnumerateInstanceExtensionProperties)(NULL, &count_ext, ext);
	VKT_NEED(92, r == VK_SUCCESS || r == VK_INCOMPLETE);
	for (uint32_t i = 0; i < count_ext; i++)
		has_props2 |= strcmp(ext[i].extensionName, props2_name) == 0;
	const char *inst_ext[2];
	if (has_props2)
		inst_ext[ici.enabledExtensionCount++] = props2_name;
#ifdef __APPLE__
	/* asked directly, MoltenVK is listed only to an instance that asks for
	 * portability drivers (through the bridge, the host asks) */
	int has_portability = 0, has_subset = 0;
	for (uint32_t i = 0; !through_bridge && i < count_ext; i++)
		has_portability |= strcmp(ext[i].extensionName, "VK_KHR_portability_enumeration") == 0;
	if (has_portability) {
		inst_ext[ici.enabledExtensionCount++] = "VK_KHR_portability_enumeration";
		ici.flags |= VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR;
	}
#endif
	ici.ppEnabledExtensionNames = inst_ext;
	/* Which version is this: the one command a renderer calls before it has
	 * an instance. (A 1.0 loader has no such command; every one since has.) */
	if (VKT(vkEnumerateInstanceVersion)) {
		uint32_t version = 0;
		VKT_STEP(90, VKT(vkEnumerateInstanceVersion)(&version));
		VKT_NEED(91, version >= VK_API_VERSION_1_0);
	}
	VKT_NEED(1, VKT(vkCreateInstance));
	VKT_STEP(2, VKT(vkCreateInstance)(&ici, NULL, &instance));

	uint32_t count = 0;
	VKT_STEP(3, VKT(vkEnumeratePhysicalDevices)(instance, &count, NULL));
	VKT_NEED(4, count >= 1);
	VkPhysicalDevice phys[8];
	if (count > 8)
		count = 8;
	r = VKT(vkEnumeratePhysicalDevices)(instance, &count, phys);
	VKT_NEED(5, r == VK_SUCCESS || r == VK_INCOMPLETE);
	/* the same device asked for twice is the same handle */
	VkPhysicalDevice again[8];
	uint32_t count2 = count;
	VKT(vkEnumeratePhysicalDevices)(instance, &count2, again);
	VKT_NEED(6, again[0] == phys[0]);
	const VkPhysicalDevice pd = phys[0];

	uint32_t families = 0;
	VKT(vkGetPhysicalDeviceQueueFamilyProperties)(pd, &families, NULL);
	VkQueueFamilyProperties family[16];
	if (families > 16)
		families = 16;
	VKT(vkGetPhysicalDeviceQueueFamilyProperties)(pd, &families, family);
	uint32_t qf = UINT32_MAX;
	for (uint32_t i = 0; i < families; i++)
		if (family[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) { qf = i; break; }
	VKT_NEED(7, qf != UINT32_MAX);

	VkPhysicalDeviceMemoryProperties mem;
	VKT(vkGetPhysicalDeviceMemoryProperties)(pd, &mem);

	const float priority = 1.0f;
	VkDeviceQueueCreateInfo qci = { .sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO, .queueFamilyIndex = qf,
	                                .queueCount = 1, .pQueuePriorities = &priority };
	VkDeviceCreateInfo dci = { .sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO, .queueCreateInfoCount = 1,
	                           .pQueueCreateInfos = &qci };
	count_ext = 512;
	r = VKT(vkEnumerateDeviceExtensionProperties)(pd, NULL, &count_ext, ext);
	VKT_NEED(93, r == VK_SUCCESS || r == VK_INCOMPLETE);
	for (uint32_t i = 0; has_props2 && i < count_ext; i++) {
		has_push |= strcmp(ext[i].extensionName, push_name) == 0;
		has_sync2 |= strcmp(ext[i].extensionName, sync2_name) == 0;
		has_eds2 |= strcmp(ext[i].extensionName, eds2_name) == 0;
		has_line |= strcmp(ext[i].extensionName, line_name) == 0;
	}
	for (uint32_t i = 0; i < count_ext; i++)
		has_templ |= strcmp(ext[i].extensionName, templ_name) == 0;
	/* the template commands, and two extensions whose commands the bridge
	 * did not have: with them on, the driver answers those commands, and the
	 * bridge must too (vkt_name_pairs) */
	if (has_templ)
		dev_ext[dev_ext_count++] = templ_name;
	if (has_eds2)
		dev_ext[dev_ext_count++] = eds2_name;
	if (has_line)
		dev_ext[dev_ext_count++] = line_name;
#ifdef __APPLE__
	/* a device that implements a subset of Vulkan is created saying so */
	for (uint32_t i = 0; has_portability && i < count_ext; i++)
		has_subset |= strcmp(ext[i].extensionName, "VK_KHR_portability_subset") == 0;
	if (has_subset)
		dev_ext[dev_ext_count++] = "VK_KHR_portability_subset";
#endif
	if (has_push) {
		/* how many may be pushed: a structure chained to the device's
		 * properties, which the driver fills in where it lies */
		PFN_vkGetPhysicalDeviceProperties2KHR props2 = (PFN_vkGetPhysicalDeviceProperties2KHR)
			VKT(vkGetInstanceProcAddr)(instance, "vkGetPhysicalDeviceProperties2KHR");
		VKT_NEED(94, props2);
		VkPhysicalDevicePushDescriptorPropertiesKHR limit = {
			.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PUSH_DESCRIPTOR_PROPERTIES_KHR };
		VkPhysicalDeviceProperties2 p2 = { .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2, .pNext = &limit };
		props2(pd, &p2);
		out->push_limit = limit.maxPushDescriptors;
		VKT_NEED(95, out->push_limit >= 1);
		dev_ext[dev_ext_count++] = push_name;
	}
	/* The extension every command of which has had a second name since 1.3:
	 * this instance asked for 1.0, so the extension's names are the ones a
	 * driver answers. */
	VkPhysicalDeviceSynchronization2FeaturesKHR sync2 = {
		.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SYNCHRONIZATION_2_FEATURES_KHR, .synchronization2 = VK_TRUE };
	if (has_sync2) {
		dev_ext[dev_ext_count++] = sync2_name;
		dci.pNext = &sync2;
	}
	dci.enabledExtensionCount = dev_ext_count;
	dci.ppEnabledExtensionNames = dev_ext;
	VkDevice dev = VK_NULL_HANDLE;
	VKT_STEP(8, VKT(vkCreateDevice)(pd, &dci, NULL, &dev));
	VkQueue queue = VK_NULL_HANDLE;
	VKT(vkGetDeviceQueue)(dev, qf, 0, &queue);
	VKT_NEED(9, queue != VK_NULL_HANDLE);

	/* ---- an image a render pass clears ---- */
	VkImageCreateInfo imci = { .sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO, .imageType = VK_IMAGE_TYPE_2D,
		.format = VK_FORMAT_R8G8B8A8_UNORM, .extent = { VKT_SIDE, VKT_SIDE, 1 }, .mipLevels = 1, .arrayLayers = 1,
		.samples = VK_SAMPLE_COUNT_1_BIT, .tiling = VK_IMAGE_TILING_OPTIMAL,
		.usage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT,
		.sharingMode = VK_SHARING_MODE_EXCLUSIVE, .initialLayout = VK_IMAGE_LAYOUT_UNDEFINED };
	VkImage image = VK_NULL_HANDLE;
	VKT_STEP(10, VKT(vkCreateImage)(dev, &imci, NULL, &image));
	VkMemoryRequirements req;
	VKT(vkGetImageMemoryRequirements)(dev, image, &req);
	int type = vkt_memory_type(&mem, req.memoryTypeBits, 0);
	VKT_NEED(11, type >= 0);
	VkMemoryAllocateInfo mai = { .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, .allocationSize = req.size,
	                             .memoryTypeIndex = (uint32_t)type };
	VkDeviceMemory image_mem = VK_NULL_HANDLE;
	VKT_STEP(12, VKT(vkAllocateMemory)(dev, &mai, NULL, &image_mem));
	VKT_STEP(13, VKT(vkBindImageMemory)(dev, image, image_mem, 0));
	VkImageViewCreateInfo vci = { .sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO, .image = image,
		.viewType = VK_IMAGE_VIEW_TYPE_2D, .format = VK_FORMAT_R8G8B8A8_UNORM,
		.subresourceRange = { VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1 } };
	VkImageView view = VK_NULL_HANDLE;
	VKT_STEP(14, VKT(vkCreateImageView)(dev, &vci, NULL, &view));

	VkAttachmentDescription att = { .format = VK_FORMAT_R8G8B8A8_UNORM, .samples = VK_SAMPLE_COUNT_1_BIT,
		.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR, .storeOp = VK_ATTACHMENT_STORE_OP_STORE,
		.stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE, .stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE,
		.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED, .finalLayout = VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL };
	VkAttachmentReference ref = { 0, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL };
	VkSubpassDescription sub = { .pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS, .colorAttachmentCount = 1,
	                             .pColorAttachments = &ref };
	VkRenderPassCreateInfo rpci = { .sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO, .attachmentCount = 1,
		.pAttachments = &att, .subpassCount = 1, .pSubpasses = &sub };
	VkRenderPass pass = VK_NULL_HANDLE;
	VKT_STEP(15, VKT(vkCreateRenderPass)(dev, &rpci, NULL, &pass));
	VkFramebufferCreateInfo fbci = { .sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO, .renderPass = pass,
		.attachmentCount = 1, .pAttachments = &view, .width = VKT_SIDE, .height = VKT_SIDE, .layers = 1 };
	VkFramebuffer fb = VK_NULL_HANDLE;
	VKT_STEP(16, VKT(vkCreateFramebuffer)(dev, &fbci, NULL, &fb));

	/* ---- three buffers the host can see: read-back, written, copied-to ---- */
	VkBuffer buf[3] = { VK_NULL_HANDLE, VK_NULL_HANDLE, VK_NULL_HANDLE };
	VkDeviceMemory buf_mem[3] = { VK_NULL_HANDLE, VK_NULL_HANDLE, VK_NULL_HANDLE };
	VkDeviceSize atom = 1;
	{
		VkPhysicalDeviceProperties props;
		VKT(vkGetPhysicalDeviceProperties)(pd, &props);
		atom = props.limits.nonCoherentAtomSize ? props.limits.nonCoherentAtomSize : 1;
	}
	(void)atom;
	for (int i = 0; i < 3; i++) {
		VkBufferCreateInfo bci = { .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, .size = VKT_BYTES,
			.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
			.sharingMode = VK_SHARING_MODE_EXCLUSIVE };
		VKT_STEP(20 + i, VKT(vkCreateBuffer)(dev, &bci, NULL, &buf[i]));
		VKT(vkGetBufferMemoryRequirements)(dev, buf[i], &req);
		type = vkt_memory_type(&mem, req.memoryTypeBits, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT);
		VKT_NEED(23 + i, type >= 0);
		VkMemoryAllocateInfo bai = { .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, .allocationSize = req.size,
		                             .memoryTypeIndex = (uint32_t)type };
		VKT_STEP(26 + i, VKT(vkAllocateMemory)(dev, &bai, NULL, &buf_mem[i]));
		VKT_STEP(29 + i, VKT(vkBindBufferMemory)(dev, buf[i], buf_mem[i], 0));
	}

	/* All three are mapped now and stay mapped while the device works, the
	 * way a renderer's upload and read-back buffers are: so what the device
	 * reads is what a FLUSH wrote out, and what is read here afterwards is
	 * what an INVALIDATE brought back - not what mapping or unmapping did. */
	void *image_bytes = NULL, *mapped = NULL, *copy_bytes = NULL;
	VKT_STEP(32, VKT(vkMapMemory)(dev, buf_mem[0], 0, VK_WHOLE_SIZE, 0, &image_bytes));
	VKT_STEP(33, VKT(vkMapMemory)(dev, buf_mem[1], 0, VK_WHOLE_SIZE, 0, &mapped));
	VKT_STEP(34, VKT(vkMapMemory)(dev, buf_mem[2], 0, VK_WHOLE_SIZE, 0, &copy_bytes));
	for (uint32_t i = 0; i < VKT_BYTES; i++)
		((uint8_t *)mapped)[i] = (uint8_t)(i * 7u + (i >> 8));
	VkMappedMemoryRange whole = { .sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE, .memory = buf_mem[1],
	                              .offset = 0, .size = VK_WHOLE_SIZE };
	VKT_STEP(35, VKT(vkFlushMappedMemoryRanges)(dev, 1, &whole));

	/* ---- the commands ---- */
	VkCommandPoolCreateInfo cpci = { .sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, .queueFamilyIndex = qf };
	VkCommandPool pool = VK_NULL_HANDLE;
	VKT_STEP(40, VKT(vkCreateCommandPool)(dev, &cpci, NULL, &pool));
	VkCommandBufferAllocateInfo cbai = { .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, .commandPool = pool,
		.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY, .commandBufferCount = 1 };
	VkCommandBuffer cmd = VK_NULL_HANDLE;
	VKT_STEP(41, VKT(vkAllocateCommandBuffers)(dev, &cbai, &cmd));
	/* a primary buffer's inheritance info is ignored: this pointer is to nothing */
	VkCommandBufferBeginInfo begin = { .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
		.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,
		.pInheritanceInfo = (const VkCommandBufferInheritanceInfo *)(uintptr_t)0x10 };
	VKT_STEP(42, VKT(vkBeginCommandBuffer)(cmd, &begin));
	VkClearValue clear = { .color = { .float32 = { 0.25f, 0.5f, 0.75f, 1.0f } } };
	VkRenderPassBeginInfo rpbi = { .sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO, .renderPass = pass,
		.framebuffer = fb, .renderArea = { { 0, 0 }, { VKT_SIDE, VKT_SIDE } }, .clearValueCount = 1,
		.pClearValues = &clear };
	VKT(vkCmdBeginRenderPass)(cmd, &rpbi, VK_SUBPASS_CONTENTS_INLINE);
	VKT(vkCmdEndRenderPass)(cmd);
	VkBufferImageCopy region = { .imageSubresource = { VK_IMAGE_ASPECT_COLOR_BIT, 0, 0, 1 },
	                             .imageExtent = { VKT_SIDE, VKT_SIDE, 1 } };
	VKT(vkCmdCopyImageToBuffer)(cmd, image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, buf[0], 1, &region);
	VkBufferCopy whole_copy = { 0, 0, VKT_BYTES };
	VKT(vkCmdCopyBuffer)(cmd, buf[1], buf[2], 1, &whole_copy);
	VKT_STEP(43, VKT(vkEndCommandBuffer)(cmd));

	VkFenceCreateInfo fci = { .sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO };
	VkFence fence = VK_NULL_HANDLE;
	VKT_STEP(44, VKT(vkCreateFence)(dev, &fci, NULL, &fence));
	VkSubmitInfo submit = { .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO, .commandBufferCount = 1, .pCommandBuffers = &cmd };
	VKT_STEP(45, VKT(vkQueueSubmit)(queue, 1, &submit, fence));
	VKT_STEP(46, VKT(vkWaitForFences)(dev, 1, &fence, VK_TRUE, 10ull * 1000 * 1000 * 1000));

	/* ---- what came out ---- */
	VkMappedMemoryRange back[2] = {
		{ .sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE, .memory = buf_mem[0], .offset = 0, .size = VK_WHOLE_SIZE },
		{ .sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE, .memory = buf_mem[2], .offset = 0, .size = VK_WHOLE_SIZE },
	};
	VKT_STEP(52, VKT(vkInvalidateMappedMemoryRanges)(dev, 2, back));
	memcpy(&out->pixel, image_bytes, 4);
	out->image_hash = vkt_hash(image_bytes, VKT_BYTES);
	out->copy_hash = vkt_hash(copy_bytes, VKT_BYTES);
	/* Through the bridge a mapping is a buffer of the guest's own. This one
	 * is scribbled over and NOT flushed, so the device still holds what it
	 * wrote; a new mapping must show that, at once and without being asked -
	 * not the scribble, and not whatever the new buffer happened to hold.
	 * (Directly, the scribble is in the driver's memory: nothing to hold.) */
	if (through_bridge)
		memset(copy_bytes, 0xEE, VKT_BYTES);
	VKT(vkUnmapMemory)(dev, buf_mem[0]);
	VKT(vkUnmapMemory)(dev, buf_mem[1]);
	VKT(vkUnmapMemory)(dev, buf_mem[2]);
	if (through_bridge) {
		VKT_STEP(54, VKT(vkMapMemory)(dev, buf_mem[2], 0, VK_WHOLE_SIZE, 0, &copy_bytes));
		out->attach_hash = vkt_hash(copy_bytes, VKT_BYTES);
		VKT(vkUnmapMemory)(dev, buf_mem[2]);
	}
	/* mapped again, the memory still holds what was flushed into it */
	VKT_STEP(53, VKT(vkMapMemory)(dev, buf_mem[1], 0, VK_WHOLE_SIZE, 0, &mapped));
	for (uint32_t i = 0; i < VKT_BYTES; i++)
		out->round_trip += ((uint8_t *)mapped)[i] == (uint8_t)(i * 7u + (i >> 8));
	VKT(vkUnmapMemory)(dev, buf_mem[1]);

	/* ---- a pipeline, a descriptor set and a draw ---- */
	VkShaderModuleCreateInfo vsci = { .sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
		.codeSize = sizeof vkt_vert_spv, .pCode = vkt_vert_spv };
	VkShaderModuleCreateInfo fsci = { .sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
		.codeSize = sizeof vkt_frag_spv, .pCode = vkt_frag_spv };
	VkShaderModule vs = VK_NULL_HANDLE, fs = VK_NULL_HANDLE;
	VKT_STEP(60, VKT(vkCreateShaderModule)(dev, &vsci, NULL, &vs));
	VKT_STEP(61, VKT(vkCreateShaderModule)(dev, &fsci, NULL, &fs));

	VkDescriptorSetLayoutBinding binding = { .binding = 0, .descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,
		.descriptorCount = 1, .stageFlags = VK_SHADER_STAGE_FRAGMENT_BIT,
		/* ignored for a uniform buffer, and so allowed to be anything */
		.pImmutableSamplers = (const VkSampler *)(uintptr_t)0x10 };
	VkDescriptorSetLayoutCreateInfo dslci = { .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
		.bindingCount = 1, .pBindings = &binding };
	VkDescriptorSetLayout set_layout = VK_NULL_HANDLE;
	VKT_STEP(62, VKT(vkCreateDescriptorSetLayout)(dev, &dslci, NULL, &set_layout));
	VkPushConstantRange push = { VK_SHADER_STAGE_FRAGMENT_BIT, 0, 16 };
	VkPipelineLayoutCreateInfo plci = { .sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO, .setLayoutCount = 1,
		.pSetLayouts = &set_layout, .pushConstantRangeCount = 1, .pPushConstantRanges = &push };
	VkPipelineLayout layout = VK_NULL_HANDLE;
	VKT_STEP(63, VKT(vkCreatePipelineLayout)(dev, &plci, NULL, &layout));

	VkDescriptorPoolSize pool_size = { VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, 1 };
	VkDescriptorPoolCreateInfo dpci = { .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO, .maxSets = 1,
		.poolSizeCount = 1, .pPoolSizes = &pool_size };
	VkDescriptorPool dpool = VK_NULL_HANDLE;
	VKT_STEP(64, VKT(vkCreateDescriptorPool)(dev, &dpci, NULL, &dpool));
	VkDescriptorSetAllocateInfo dsai = { .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
		.descriptorPool = dpool, .descriptorSetCount = 1, .pSetLayouts = &set_layout };
	VkDescriptorSet set = VK_NULL_HANDLE;
	VKT_STEP(65, VKT(vkAllocateDescriptorSets)(dev, &dsai, &set));
	/* a pool reset and filled again, as many renderers do every frame: through
	 * the bridge the table of handles must not grow with it (run_vk.c) */
	for (int k = 0; k < 1000; k++) {
		VKT_STEP(65, VKT(vkResetDescriptorPool)(dev, dpool, 0));
		VKT_STEP(65, VKT(vkAllocateDescriptorSets)(dev, &dsai, &set));
	}
	/* and an object made and destroyed a thousand times: its slot too is
	 * given out again (2026-10-18) */
	for (int k = 0; k < 1000; k++) {
		VkSemaphoreCreateInfo sci = { .sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO };
		VkSemaphore made = VK_NULL_HANDLE;
		VKT_STEP(65, VKT(vkCreateSemaphore)(dev, &sci, NULL, &made));
		VKT(vkDestroySemaphore)(dev, made, NULL);
	}

	VkBuffer ubo = VK_NULL_HANDLE, vbo = VK_NULL_HANDLE;
	VkDeviceMemory ubo_mem = VK_NULL_HANDLE, vbo_mem = VK_NULL_HANDLE;
	void *ubo_bytes = NULL, *vbo_bytes = NULL;
	VKT_STEP(66, vkt_buffer(get, dev, &mem, 256, VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT, &ubo, &ubo_mem, &ubo_bytes));
	VKT_STEP(67, vkt_buffer(get, dev, &mem, 256, VK_BUFFER_USAGE_VERTEX_BUFFER_BIT, &vbo, &vbo_mem, &vbo_bytes));
	const float colour[4] = { 0.5f, 0.25f, 0.0f, 0.5f };
	const float corners[6] = { -1.0f, -1.0f, 1.0f, -1.0f, -1.0f, 1.0f };   /* the upper left half */
	memcpy(ubo_bytes, colour, sizeof colour);
	memcpy(vbo_bytes, corners, sizeof corners);
	VkMappedMemoryRange written[2] = {
		{ .sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE, .memory = ubo_mem, .offset = 0, .size = VK_WHOLE_SIZE },
		{ .sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE, .memory = vbo_mem, .offset = 0, .size = VK_WHOLE_SIZE },
	};
	VKT_STEP(68, VKT(vkFlushMappedMemoryRanges)(dev, 2, written));

	/* Only the array the descriptor's type names is read; the other two
	 * point at nothing, as a renderer's may. */
	VkDescriptorBufferInfo ubo_info = { ubo, 0, 16 };
	VkWriteDescriptorSet write = { .sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, .dstSet = set, .dstBinding = 0,
		.descriptorCount = 1, .descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, .pBufferInfo = &ubo_info,
		.pImageInfo = (const VkDescriptorImageInfo *)(uintptr_t)0x10,
		.pTexelBufferView = (const VkBufferView *)(uintptr_t)0x10 };
	VKT(vkUpdateDescriptorSets)(dev, 1, &write, 0, NULL);
	if (through_bridge) {
		/* A write with a count and no array at all is a null pointer a driver
		 * follows. The bridge must refuse it and leave the set as it was. */
		VkWriteDescriptorSet nothing = write;
		nothing.pBufferInfo = NULL;
		VKT(vkUpdateDescriptorSets)(dev, 1, &nothing, 0, NULL);
		/* So is a write to a set that does not exist: refused, too. */
		VkWriteDescriptorSet nowhere = write;
		nowhere.dstSet = (VkDescriptorSet)(uintptr_t)0x7fff00000010ull;
		VKT(vkUpdateDescriptorSets)(dev, 1, &nowhere, 0, NULL);
		/* And an image view the bridge never made, in a write whose type
		 * reads it: passed on as nothing, the driver would follow it. */
		VkDescriptorImageInfo no_view = { VK_NULL_HANDLE, (VkImageView)(uintptr_t)0x7fff00000030ull,
			VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL };
		VkWriteDescriptorSet viewless = write;
		viewless.descriptorType = VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE;
		viewless.pImageInfo = &no_view;
		viewless.pBufferInfo = NULL;
		VKT(vkUpdateDescriptorSets)(dev, 1, &viewless, 0, NULL);
	}

	VkPipelineShaderStageCreateInfo stages[2] = {
		{ .sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO, .stage = VK_SHADER_STAGE_VERTEX_BIT,
		  .module = vs, .pName = "main" },
		{ .sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO, .stage = VK_SHADER_STAGE_FRAGMENT_BIT,
		  .module = fs, .pName = "main" },
	};
	VkVertexInputBindingDescription vbind = { 0, 8, VK_VERTEX_INPUT_RATE_VERTEX };
	VkVertexInputAttributeDescription vattr = { 0, 0, VK_FORMAT_R32G32_SFLOAT, 0 };
	VkPipelineVertexInputStateCreateInfo vin = { .sType = VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO,
		.vertexBindingDescriptionCount = 1, .pVertexBindingDescriptions = &vbind,
		.vertexAttributeDescriptionCount = 1, .pVertexAttributeDescriptions = &vattr };
	VkPipelineInputAssemblyStateCreateInfo ia = { .sType = VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO,
		.topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST };
	VkViewport viewport = { 0.0f, 0.0f, VKT_SIDE, VKT_SIDE, 0.0f, 1.0f };
	VkRect2D scissor = { { 0, 0 }, { VKT_SIDE, VKT_SIDE } };
	VkPipelineViewportStateCreateInfo vp = { .sType = VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO,
		.viewportCount = 1, .pViewports = &viewport, .scissorCount = 1, .pScissors = &scissor };
	VkPipelineRasterizationStateCreateInfo rs = { .sType = VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO,
		.polygonMode = VK_POLYGON_MODE_FILL, .cullMode = VK_CULL_MODE_NONE,
		.frontFace = VK_FRONT_FACE_COUNTER_CLOCKWISE, .lineWidth = 1.0f };
	VkPipelineMultisampleStateCreateInfo ms = { .sType = VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO,
		.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT };
	VkPipelineColorBlendAttachmentState blend_att = { .colorWriteMask = 0xf };
	VkPipelineColorBlendStateCreateInfo blend = { .sType = VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO,
		.attachmentCount = 1, .pAttachments = &blend_att };
	VkGraphicsPipelineCreateInfo gpci = { .sType = VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO, .stageCount = 2,
		.pStages = stages, .pVertexInputState = &vin, .pInputAssemblyState = &ia, .pViewportState = &vp,
		.pRasterizationState = &rs, .pMultisampleState = &ms, .pColorBlendState = &blend, .layout = layout,
		.renderPass = pass, .subpass = 0 };
	VkPipeline pipeline = VK_NULL_HANDLE;
	VKT_STEP(69, VKT(vkCreateGraphicsPipelines)(dev, VK_NULL_HANDLE, 1, &gpci, NULL, &pipeline));
	if (through_bridge) {
		/* A pipeline whose layout the bridge never made: refused, and the
		 * pipeline left null. Passed on as nothing, the driver would follow it. */
		VkGraphicsPipelineCreateInfo layoutless = gpci;
		layoutless.layout = (VkPipelineLayout)(uintptr_t)0x7fff00000040ull;
		VkPipeline none = VK_NULL_HANDLE;
		VKT(vkCreateGraphicsPipelines)(dev, VK_NULL_HANDLE, 1, &layoutless, NULL, &none);
		if (none != VK_NULL_HANDLE) { out->failed_at = 169; return; }
	}

	VkCommandBuffer draw = VK_NULL_HANDLE;
	VKT_STEP(70, VKT(vkAllocateCommandBuffers)(dev, &cbai, &draw));
	VKT_NEED(71, draw != cmd);
	VKT_STEP(72, VKT(vkMapMemory)(dev, buf_mem[0], 0, VK_WHOLE_SIZE, 0, &image_bytes));   /* before the device works */
	VkCommandBufferBeginInfo draw_begin = { .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
	VKT_STEP(73, VKT(vkBeginCommandBuffer)(draw, &draw_begin));
	VkClearValue black = { .color = { .float32 = { 0.0f, 0.0f, 0.0f, 1.0f } } };
	rpbi.pClearValues = &black;
	VKT(vkCmdBeginRenderPass)(draw, &rpbi, VK_SUBPASS_CONTENTS_INLINE);
	VKT(vkCmdBindPipeline)(draw, VK_PIPELINE_BIND_POINT_GRAPHICS, pipeline);
	VKT(vkCmdBindDescriptorSets)(draw, VK_PIPELINE_BIND_POINT_GRAPHICS, layout, 0, 1, &set, 0, NULL);
	const float add[4] = { 0.25f, 0.25f, 0.5f, 0.5f };
	VKT(vkCmdPushConstants)(draw, layout, VK_SHADER_STAGE_FRAGMENT_BIT, 0, sizeof add, add);
	const VkDeviceSize zero = 0;
	VKT(vkCmdBindVertexBuffers)(draw, 0, 1, &vbo, &zero);
	VKT(vkCmdDraw)(draw, 3, 1, 0, 0);
	VKT(vkCmdEndRenderPass)(draw);
	VKT(vkCmdCopyImageToBuffer)(draw, image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, buf[0], 1, &region);
	VKT_STEP(74, VKT(vkEndCommandBuffer)(draw));
	VKT_STEP(75, VKT(vkResetFences)(dev, 1, &fence));
	submit.pCommandBuffers = &draw;
	VKT_STEP(76, VKT(vkQueueSubmit)(queue, 1, &submit, fence));
	VKT_STEP(77, VKT(vkWaitForFences)(dev, 1, &fence, VK_TRUE, 10ull * 1000 * 1000 * 1000));
	VKT_STEP(78, VKT(vkInvalidateMappedMemoryRanges)(dev, 1, back));
	memcpy(&out->drawn_inside, (const uint8_t *)image_bytes + (8 * VKT_SIDE + 8) * 4, 4);
	memcpy(&out->drawn_outside, (const uint8_t *)image_bytes + (60 * VKT_SIDE + 60) * 4, 4);
	out->drawn_hash = vkt_hash(image_bytes, VKT_BYTES);

	/* ---- the same draw, its uniform pushed ---- */
	if (has_push) {
		PFN_vkCmdPushDescriptorSetKHR push_set = (PFN_vkCmdPushDescriptorSetKHR)
			VKT(vkGetDeviceProcAddr)(dev, "vkCmdPushDescriptorSetKHR");
		VKT_NEED(100, push_set);
		VkDescriptorSetLayoutCreateInfo pushed_dslci = dslci;
		pushed_dslci.flags = VK_DESCRIPTOR_SET_LAYOUT_CREATE_PUSH_DESCRIPTOR_BIT_KHR;
		VkDescriptorSetLayout pushed_set_layout = VK_NULL_HANDLE;
		VKT_STEP(101, VKT(vkCreateDescriptorSetLayout)(dev, &pushed_dslci, NULL, &pushed_set_layout));
		VkPipelineLayoutCreateInfo pushed_plci = plci;
		pushed_plci.pSetLayouts = &pushed_set_layout;
		VkPipelineLayout pushed_layout = VK_NULL_HANDLE;
		VKT_STEP(102, VKT(vkCreatePipelineLayout)(dev, &pushed_plci, NULL, &pushed_layout));
		VkGraphicsPipelineCreateInfo pushed_gpci = gpci;
		pushed_gpci.layout = pushed_layout;
		VkPipeline pushed_pipeline = VK_NULL_HANDLE;
		VKT_STEP(103, VKT(vkCreateGraphicsPipelines)(dev, VK_NULL_HANDLE, 1, &pushed_gpci, NULL, &pushed_pipeline));

		/* another colour, so that the picture says which uniform was read */
		VkBuffer ubo2 = VK_NULL_HANDLE;
		VkDeviceMemory ubo2_mem = VK_NULL_HANDLE;
		void *ubo2_bytes = NULL;
		VKT_STEP(104, vkt_buffer(get, dev, &mem, 256, VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT, &ubo2, &ubo2_mem, &ubo2_bytes));
		const float colour2[4] = { 0.0f, 0.5f, 0.25f, 0.5f };
		memcpy(ubo2_bytes, colour2, sizeof colour2);
		VkMappedMemoryRange written2 = { .sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE, .memory = ubo2_mem,
		                                 .offset = 0, .size = VK_WHOLE_SIZE };
		VKT_STEP(105, VKT(vkFlushMappedMemoryRanges)(dev, 1, &written2));

		VkCommandBuffer pushed = VK_NULL_HANDLE;
		VKT_STEP(106, VKT(vkAllocateCommandBuffers)(dev, &cbai, &pushed));
		VKT_STEP(107, VKT(vkBeginCommandBuffer)(pushed, &draw_begin));
		VKT(vkCmdBeginRenderPass)(pushed, &rpbi, VK_SUBPASS_CONTENTS_INLINE);
		VKT(vkCmdBindPipeline)(pushed, VK_PIPELINE_BIND_POINT_GRAPHICS, pushed_pipeline);
		/* a pushed write's set is ignored, and so allowed to be anything */
		VkDescriptorBufferInfo ubo2_info = { ubo2, 0, 16 };
		VkWriteDescriptorSet pushed_write = { .sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
			.dstSet = (VkDescriptorSet)(uintptr_t)0x7fff00000010ull, .dstBinding = 0, .descriptorCount = 1,
			.descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, .pBufferInfo = &ubo2_info };
		push_set(pushed, VK_PIPELINE_BIND_POINT_GRAPHICS, pushed_layout, 0, 1, &pushed_write);
		VKT(vkCmdPushConstants)(pushed, pushed_layout, VK_SHADER_STAGE_FRAGMENT_BIT, 0, sizeof add, add);
		VKT(vkCmdBindVertexBuffers)(pushed, 0, 1, &vbo, &zero);
		VKT(vkCmdDraw)(pushed, 3, 1, 0, 0);
		VKT(vkCmdEndRenderPass)(pushed);
		VKT(vkCmdCopyImageToBuffer)(pushed, image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, buf[0], 1, &region);
		VKT_STEP(108, VKT(vkEndCommandBuffer)(pushed));
		VKT_STEP(109, VKT(vkResetFences)(dev, 1, &fence));
		submit.pCommandBuffers = &pushed;
		VKT_STEP(110, VKT(vkQueueSubmit)(queue, 1, &submit, fence));
		VKT_STEP(111, VKT(vkWaitForFences)(dev, 1, &fence, VK_TRUE, 10ull * 1000 * 1000 * 1000));
		VKT_STEP(112, VKT(vkInvalidateMappedMemoryRanges)(dev, 1, back));
		memcpy(&out->pushed_inside, (const uint8_t *)image_bytes + (8 * VKT_SIDE + 8) * 4, 4);
		out->pushed_hash = vkt_hash(image_bytes, VKT_BYTES);

		/* ---- and pushed through a template ----
		 * The data a template reads holds the buffer's handle at an offset
		 * only the template knows; through the bridge it is the guest's
		 * handle until the host translates it by the template's entries.
		 * Yet another colour, so the picture says this uniform was read. */
		if (has_templ) {
			PFN_vkCreateDescriptorUpdateTemplateKHR make_templ = (PFN_vkCreateDescriptorUpdateTemplateKHR)
				VKT(vkGetDeviceProcAddr)(dev, "vkCreateDescriptorUpdateTemplateKHR");
			PFN_vkDestroyDescriptorUpdateTemplateKHR drop_templ = (PFN_vkDestroyDescriptorUpdateTemplateKHR)
				VKT(vkGetDeviceProcAddr)(dev, "vkDestroyDescriptorUpdateTemplateKHR");
			PFN_vkCmdPushDescriptorSetWithTemplateKHR push_templ = (PFN_vkCmdPushDescriptorSetWithTemplateKHR)
				VKT(vkGetDeviceProcAddr)(dev, "vkCmdPushDescriptorSetWithTemplateKHR");
			VKT_NEED(130, make_templ && drop_templ && push_templ);
			VkBuffer ubo3 = VK_NULL_HANDLE;
			VkDeviceMemory ubo3_mem = VK_NULL_HANDLE;
			void *ubo3_bytes = NULL;
			VKT_STEP(131, vkt_buffer(get, dev, &mem, 256, VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT, &ubo3, &ubo3_mem, &ubo3_bytes));
			const float colour3[4] = { 0.5f, 0.0f, 0.5f, 0.5f };
			memcpy(ubo3_bytes, colour3, sizeof colour3);
			VkMappedMemoryRange written3 = { .sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE, .memory = ubo3_mem,
			                                 .offset = 0, .size = VK_WHOLE_SIZE };
			VKT_STEP(132, VKT(vkFlushMappedMemoryRanges)(dev, 1, &written3));
			struct vkt_templ_data data = { 0x5555555555555555ull, { ubo3, 0, 16 } };
			VkDescriptorUpdateTemplateEntry entry = { .dstBinding = 0, .dstArrayElement = 0, .descriptorCount = 1,
				.descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, .offset = offsetof(struct vkt_templ_data, info),
				.stride = sizeof(VkDescriptorBufferInfo) };
			VkDescriptorUpdateTemplateCreateInfo tci = { .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_UPDATE_TEMPLATE_CREATE_INFO,
				.descriptorUpdateEntryCount = 1, .pDescriptorUpdateEntries = &entry,
				.templateType = VK_DESCRIPTOR_UPDATE_TEMPLATE_TYPE_PUSH_DESCRIPTORS_KHR,
				.descriptorSetLayout = pushed_set_layout, .pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS,
				.pipelineLayout = pushed_layout, .set = 0 };
			VkDescriptorUpdateTemplate templ = VK_NULL_HANDLE;
			VKT_STEP(133, make_templ(dev, &tci, NULL, &templ));
			VkCommandBuffer templated = VK_NULL_HANDLE;
			VKT_STEP(134, VKT(vkAllocateCommandBuffers)(dev, &cbai, &templated));
			VKT_STEP(135, VKT(vkBeginCommandBuffer)(templated, &draw_begin));
			VKT(vkCmdBeginRenderPass)(templated, &rpbi, VK_SUBPASS_CONTENTS_INLINE);
			VKT(vkCmdBindPipeline)(templated, VK_PIPELINE_BIND_POINT_GRAPHICS, pushed_pipeline);
			push_templ(templated, templ, pushed_layout, 0, &data);
			VKT(vkCmdPushConstants)(templated, pushed_layout, VK_SHADER_STAGE_FRAGMENT_BIT, 0, sizeof add, add);
			VKT(vkCmdBindVertexBuffers)(templated, 0, 1, &vbo, &zero);
			VKT(vkCmdDraw)(templated, 3, 1, 0, 0);
			VKT(vkCmdEndRenderPass)(templated);
			VKT(vkCmdCopyImageToBuffer)(templated, image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, buf[0], 1, &region);
			VKT_STEP(136, VKT(vkEndCommandBuffer)(templated));
			VKT_STEP(137, VKT(vkResetFences)(dev, 1, &fence));
			submit.pCommandBuffers = &templated;
			VKT_STEP(138, VKT(vkQueueSubmit)(queue, 1, &submit, fence));
			VKT_STEP(139, VKT(vkWaitForFences)(dev, 1, &fence, VK_TRUE, 10ull * 1000 * 1000 * 1000));
			VKT_STEP(140, VKT(vkInvalidateMappedMemoryRanges)(dev, 1, back));
			memcpy(&out->templ_inside, (const uint8_t *)image_bytes + (8 * VKT_SIDE + 8) * 4, 4);
			out->templ_hash = vkt_hash(image_bytes, VKT_BYTES);
			drop_templ(dev, templ, NULL);
			VKT(vkUnmapMemory)(dev, ubo3_mem);
			VKT(vkDestroyBuffer)(dev, ubo3, NULL);
			VKT(vkFreeMemory)(dev, ubo3_mem, NULL);
		}

		VKT(vkDestroyPipeline)(dev, pushed_pipeline, NULL);
		VKT(vkUnmapMemory)(dev, ubo2_mem);
		VKT(vkDestroyBuffer)(dev, ubo2, NULL);
		VKT(vkFreeMemory)(dev, ubo2_mem, NULL);
		VKT(vkDestroyPipelineLayout)(dev, pushed_layout, NULL);
		VKT(vkDestroyDescriptorSetLayout)(dev, pushed_set_layout, NULL);
	}
	/* A command has the name of each extension it came through and one more
	 * since it joined a version. Which the device has is the driver's to say:
	 * a command it does not have answers nothing (the bridge used to answer
	 * every name it knew, and a call was then refused). One it has answers
	 * to every name through the bridge, with the same function, whichever
	 * name the driver gave (chimera issue 268). */
	for (size_t i = 0; i < sizeof vkt_name_pairs / sizeof vkt_name_pairs[0]; i++) {
		const PFN_vkVoidFunction one = VKT(vkGetDeviceProcAddr)(dev, vkt_name_pairs[i][0]);
		const PFN_vkVoidFunction two = VKT(vkGetDeviceProcAddr)(dev, vkt_name_pairs[i][1]);
		if (one || two)
			out->names_present |= 1u << i;
		if (through_bridge)
			VKT_NEED(116, one == two);
	}
	if (has_sync2) {
		/* And one of them is called: a command in the queue sets an event,
		 * and the event is then set. The command is asked for by the
		 * extension's name, which is the only one a driver need answer to
		 * a program that asked for Vulkan 1.0. A bridge that asked the
		 * driver for the newer name alone had nothing to call: the event
		 * stayed as it was, and a renderer waiting for it waited for good. */
		const PFN_vkCmdSetEvent2KHR set2 = (PFN_vkCmdSetEvent2KHR)VKT(vkGetDeviceProcAddr)(dev, "vkCmdSetEvent2KHR");
		VKT_NEED(117, set2);
		VkEventCreateInfo eci = { .sType = VK_STRUCTURE_TYPE_EVENT_CREATE_INFO };
		VkEvent event = VK_NULL_HANDLE;
		VKT_STEP(118, VKT(vkCreateEvent)(dev, &eci, NULL, &event));
		VKT_NEED(119, VKT(vkGetEventStatus)(dev, event) == VK_EVENT_RESET);
		VkCommandBuffer ev = VK_NULL_HANDLE;
		VKT_STEP(120, VKT(vkAllocateCommandBuffers)(dev, &cbai, &ev));
		VKT_STEP(121, VKT(vkBeginCommandBuffer)(ev, &begin));
		VkMemoryBarrier2KHR barrier = { .sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER_2_KHR,
			.srcStageMask = VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT_KHR,
			.srcAccessMask = VK_ACCESS_2_MEMORY_READ_BIT_KHR | VK_ACCESS_2_MEMORY_WRITE_BIT_KHR,
			.dstStageMask = VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT_KHR,
			.dstAccessMask = VK_ACCESS_2_MEMORY_READ_BIT_KHR | VK_ACCESS_2_MEMORY_WRITE_BIT_KHR };
		VkDependencyInfoKHR dependency = { .sType = VK_STRUCTURE_TYPE_DEPENDENCY_INFO_KHR,
			.memoryBarrierCount = 1, .pMemoryBarriers = &barrier };
		set2(ev, event, &dependency);
		VKT_STEP(122, VKT(vkEndCommandBuffer)(ev));
		VKT_STEP(123, VKT(vkResetFences)(dev, 1, &fence));
		submit.pCommandBuffers = &ev;
		VKT_STEP(124, VKT(vkQueueSubmit)(queue, 1, &submit, fence));
		VKT_STEP(125, VKT(vkWaitForFences)(dev, 1, &fence, VK_TRUE, 10ull * 1000 * 1000 * 1000));
		VKT_NEED(126, VKT(vkGetEventStatus)(dev, event) == VK_EVENT_SET);
		out->event_set = 1;
		VKT(vkDestroyEvent)(dev, event, NULL);
	}
	VKT(vkUnmapMemory)(dev, buf_mem[0]);

	VKT(vkDestroyPipeline)(dev, pipeline, NULL);
	VKT(vkUnmapMemory)(dev, ubo_mem);
	VKT(vkUnmapMemory)(dev, vbo_mem);
	VKT(vkDestroyBuffer)(dev, ubo, NULL);
	VKT(vkDestroyBuffer)(dev, vbo, NULL);
	VKT(vkFreeMemory)(dev, ubo_mem, NULL);
	VKT(vkFreeMemory)(dev, vbo_mem, NULL);
	VKT(vkDestroyDescriptorPool)(dev, dpool, NULL);     /* and the set with it */
	VKT(vkDestroyPipelineLayout)(dev, layout, NULL);
	VKT(vkDestroyDescriptorSetLayout)(dev, set_layout, NULL);
	VKT(vkDestroyShaderModule)(dev, vs, NULL);
	VKT(vkDestroyShaderModule)(dev, fs, NULL);

	VKT(vkDestroyFence)(dev, fence, NULL);
	VKT(vkFreeCommandBuffers)(dev, pool, 1, &cmd);
	VKT(vkDestroyCommandPool)(dev, pool, NULL);
	for (int i = 0; i < 3; i++) {
		VKT(vkDestroyBuffer)(dev, buf[i], NULL);
		VKT(vkFreeMemory)(dev, buf_mem[i], NULL);
	}
	VKT(vkDestroyFramebuffer)(dev, fb, NULL);
	VKT(vkDestroyRenderPass)(dev, pass, NULL);
	VKT(vkDestroyImageView)(dev, view, NULL);
	VKT(vkDestroyImage)(dev, image, NULL);
	VKT(vkFreeMemory)(dev, image_mem, NULL);
	VKT(vkDestroyDevice)(dev, NULL);
	VKT(vkDestroyInstance)(instance, NULL);
}
