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
 * that counts, push constants, a vertex buffer and a second command buffer. */
#pragma once

#include <vulkan/vulkan_core.h>
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
	uint32_t drawn_inside;  /* a pixel the triangle covers */
	uint32_t drawn_outside; /* one it does not */
	uint64_t drawn_hash;    /* every byte of the drawn image */
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
	memset(out, 0, sizeof *out);

	VkApplicationInfo app = { .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO, .pApplicationName = "vktest",
	                          .apiVersion = VK_API_VERSION_1_0 };
	VkInstanceCreateInfo ici = { .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, .pApplicationInfo = &app };
	VkInstance instance = VK_NULL_HANDLE;
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
	VKT(vkUnmapMemory)(dev, buf_mem[0]);
	VKT(vkUnmapMemory)(dev, buf_mem[1]);
	VKT(vkUnmapMemory)(dev, buf_mem[2]);
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
