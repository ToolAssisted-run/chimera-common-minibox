#define _GNU_SOURCE
/* The Vulkan bridge, end to end: the same test (vktest.h) run against the
 * machine's driver directly and from inside a guest through the bridge, and
 * the two compared; then what a savestate load does to a handle a guest
 * still holds. Exit 77 (skipped) on a machine with no Vulkan device. */
#include "minibox.h"
#include "vk-host.h"
#include "vktest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

static void *s_native_lib;

static void *native_lookup(const char *name)
{
#ifdef _WIN32
	return (void *)GetProcAddress((HMODULE)s_native_lib, name);
#else
	return dlsym(s_native_lib, name);
#endif
}

typedef struct { FILE *f; } freader;
static intptr_t file_read(uintptr_t ud, uint8_t *data, uintptr_t size)
{
	return (intptr_t)fread(data, 1, size, ((freader *)ud)->f);
}

static mb_host *g_host;

static uintptr_t proc(const char *name)
{
	mb_return r;
	wbx_get_proc_addr(g_host, name, &r);
	if (r.error_message[0]) {
		fprintf(stderr, "get_proc_addr(%s): %s\n", name, r.error_message);
		exit(2);
	}
	return r.data;
}

typedef int      (MB_GUEST_ABI *int_fn)(void);
typedef int      (MB_GUEST_ABI *install_fn)(uint64_t);
typedef uint64_t (MB_GUEST_ABI *value_fn)(int);
typedef uint64_t (MB_GUEST_ABI *u64_fn)(void);

static int failures;
#define EXPECT(cond, ...) do { if (!(cond)) { failures++; fprintf(stderr, "FAIL: " __VA_ARGS__); fprintf(stderr, "\n"); } } while (0)

/* Which device the direct run uses, so that the bridge is told to use the
 * same one: the comparison is of two paths to ONE driver. */
static int first_device_name(char *out, size_t size)
{
	VkInstanceCreateInfo ici = { .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO };
	VkInstance instance = VK_NULL_HANDLE;
	PFN_vkCreateInstance create = (PFN_vkCreateInstance)native_lookup("vkCreateInstance");
	if (!create || create(&ici, NULL, &instance) != VK_SUCCESS)
		return 0;
	uint32_t n = 1;
	VkPhysicalDevice pd = VK_NULL_HANDLE;
	const VkResult r = ((PFN_vkEnumeratePhysicalDevices)native_lookup("vkEnumeratePhysicalDevices"))(instance, &n, &pd);
	int ok = 0;
	if ((r == VK_SUCCESS || r == VK_INCOMPLETE) && n == 1) {
		VkPhysicalDeviceProperties p;
		((PFN_vkGetPhysicalDeviceProperties)native_lookup("vkGetPhysicalDeviceProperties"))(pd, &p);
		snprintf(out, size, "%s", p.deviceName);
		ok = 1;
	}
	((PFN_vkDestroyInstance)native_lookup("vkDestroyInstance"))(instance, NULL);
	return ok;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: run_vk <guest.wbx>\n");
		return 2;
	}
	char err[256] = "";
	if (chimera_vk_host_init(err, sizeof err) != 0) {
		fprintf(stderr, "SKIP: %s\n", err);
		return 77;
	}
#ifdef _WIN32
	s_native_lib = (void *)LoadLibraryA("vulkan-1.dll");
#else
	s_native_lib = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
#endif
	char device[256] = "";
	if (!s_native_lib || !first_device_name(device, sizeof device)) {
		fprintf(stderr, "SKIP: this machine's Vulkan loader has no device\n");
		return 77;
	}
#ifdef _WIN32
	SetEnvironmentVariableA("CHIMERA_VK_DEVICE", device);
	_putenv_s("CHIMERA_VK_DEVICE", device);
#else
	setenv("CHIMERA_VK_DEVICE", device, 1);
#endif

	/* ---- directly ---- */
	struct vkt_result direct;
	vkt_run(native_lookup, &direct);
	EXPECT(direct.failed_at == 0, "the direct run failed at step %d (VkResult %d)", direct.failed_at, direct.vk_result);
	if (direct.failed_at)
		return 1;

	/* ---- through the bridge ---- */
	FILE *f = fopen(argv[1], "rb");
	if (!f) {
		fprintf(stderr, "cannot open %s\n", argv[1]);
		return 2;
	}
	mb_memory_layout_template layout = {
		.sbrk_size = 64u << 20, .sealed_size = 16u << 20, .invis_size = 16u << 20,
		.plain_size = 16u << 20, .mmap_size = 64u << 20,
	};
	freader fr = { f };
	mb_return r;
	wbx_create_host(&layout, "guest.wbx", file_read, (uintptr_t)&fr, &r);
	fclose(f);
	if (r.error_message[0]) {
		fprintf(stderr, "create_host: %s\n", r.error_message);
		return 2;
	}
	g_host = (mb_host *)r.data;
	wbx_activate_host(g_host, &r);
	wbx_get_callback_addr(g_host, (mb_external_callback)chimera_vk_host_dispatch, 0, &r);
	const uintptr_t bridge = r.data;
	EXPECT(bridge != 0, "the callback was not registered");

	const install_fn install = (install_fn)proc("Install");
	const int_fn run = (int_fn)proc("Run");
	const value_fn value = (value_fn)proc("Value");
	const u64_fn context_id = (u64_fn)proc("ContextId");
	const int_fn make_instance = (int_fn)proc("MakeInstance");
	const int_fn ask_kept = (int_fn)proc("AskKeptInstance");
	const u64_fn kept = (u64_fn)proc("KeptInstance");
	const int_fn make_fresh = (int_fn)proc("MakeFreshInstance");
	const int_fn ask_fresh = (int_fn)proc("AskFreshInstance");
	const u64_fn fresh = (u64_fn)proc("FreshInstance");
	const int_fn destroy_fresh = (int_fn)proc("DestroyFreshInstance");

	EXPECT(install(bridge) == 1, "the guest refused the bridge");
	const int failed = run();
	EXPECT(failed == 0, "the bridged run failed at step %d (VkResult %d)", failed, (int)(int64_t)value(1));
	fprintf(stderr, "device: %s\n", chimera_vk_host_description());
	fprintf(stderr, "direct : pixel %08x image %016llx copy %016llx round trip %u\n", direct.pixel,
		(unsigned long long)direct.image_hash, (unsigned long long)direct.copy_hash, direct.round_trip);
	fprintf(stderr, "bridged: pixel %08x image %016llx copy %016llx round trip %u\n", (uint32_t)value(2),
		(unsigned long long)value(3), (unsigned long long)value(4), (uint32_t)value(5));

	uint8_t pattern[VKT_BYTES];
	for (uint32_t i = 0; i < VKT_BYTES; i++)
		pattern[i] = (uint8_t)(i * 7u + (i >> 8));
	const uint64_t pattern_hash = vkt_hash(pattern, VKT_BYTES);

	/* the clear colour is (0.25, 0.5, 0.75, 1): the driver rounds, so the two
	 * channels that fall between bytes are held to either neighbour */
	const uint8_t *px = (const uint8_t *)&direct.pixel;
	EXPECT((px[0] == 0x3f || px[0] == 0x40) && (px[1] == 0x7f || px[1] == 0x80) &&
	       (px[2] == 0xbf || px[2] == 0xc0) && px[3] == 0xff,
	       "the direct run's pixel %02x %02x %02x %02x is not the clear colour", px[0], px[1], px[2], px[3]);
	EXPECT((uint32_t)value(2) == direct.pixel, "the pixel differs through the bridge");
	EXPECT(value(3) == direct.image_hash, "the image read back differs through the bridge");
	EXPECT(direct.copy_hash == pattern_hash, "the direct run's copied buffer is not what was written");
	EXPECT(value(4) == pattern_hash, "what the guest wrote through a mapping is not what the device copied");
	EXPECT(direct.round_trip == VKT_BYTES && value(5) == VKT_BYTES,
	       "a second mapping gave back %u of %u bytes directly, %u through the bridge",
	       direct.round_trip, (unsigned)VKT_BYTES, (unsigned)value(5));

	long last = -1;
	EXPECT(chimera_vk_host_refused(&last) == 0, "%lu calls were refused in a correct run (last opcode %ld)",
	       chimera_vk_host_refused(NULL), last);

	/* ---- a handle from before a load ---- */
	const uint64_t before = context_id();
	EXPECT(before != 0, "the context has no id");
	EXPECT(make_instance() == VK_SUCCESS, "the guest could not make an instance to keep");
	const uint64_t handle = kept();
	EXPECT(handle != 0 && handle < (1ull << 40), "the guest's handle %llx is not a small counter",
	       (unsigned long long)handle);
	chimera_vk_host_state_loaded();
	EXPECT(context_id() != before && context_id() != 0, "a load did not change the context id");
	/* The new context makes an instance of its own, which takes the place in
	 * the table the kept one had: the two differ only in which context. */
	EXPECT(make_fresh() == VK_SUCCESS, "the new context could not make an instance");
	EXPECT((uint32_t)fresh() == (uint32_t)handle && fresh() != handle,
	       "the new instance %llx was meant to share the kept one's place (%llx) and not its context",
	       (unsigned long long)fresh(), (unsigned long long)handle);
	const unsigned long refused_before = chimera_vk_host_refused(NULL);
	EXPECT(ask_kept() == VK_ERROR_DEVICE_LOST, "a handle from before the load was not answered with DEVICE_LOST");
	EXPECT(chimera_vk_host_refused(NULL) == refused_before + 1, "the stale call was not counted as refused");
	EXPECT(ask_fresh() == VK_SUCCESS, "the new context's own instance was refused");
	destroy_fresh();

	/* and the new context works, with the same result */
	const int failed_again = run();
	EXPECT(failed_again == 0, "after a load the run failed at step %d (VkResult %d)", failed_again, (int)(int64_t)value(1));
	EXPECT(value(3) == direct.image_hash && value(4) == pattern_hash, "after a load the results differ");

	wbx_deactivate_host(g_host, &r);
	chimera_vk_host_shutdown();
	if (failures) {
		fprintf(stderr, "%d failed\n", failures);
		return 1;
	}
	fprintf(stderr, "vk bridge: ok\n");
	return 0;
}
