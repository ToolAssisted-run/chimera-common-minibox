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
#ifdef __APPLE__
	/* MoltenVK is listed only to an instance that asks for portability drivers */
	static const char *const portability[] = { "VK_KHR_portability_enumeration" };
	ici.flags = VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR;
	ici.enabledExtensionCount = 1;
	ici.ppEnabledExtensionNames = portability;
#endif
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
	s_native_lib = chimera_vk_host_open_loader();
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
	vkt_run(native_lookup, &direct, 0);
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
	const int_fn keep_card = (int_fn)proc("KeepCard");
	const u64_fn ask_kept_card = (u64_fn)proc("AskKeptCard");
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
	EXPECT(value(12) == pattern_hash, "a new mapping of memory the device wrote does not show what it wrote");
	EXPECT(direct.round_trip == VKT_BYTES && value(5) == VKT_BYTES,
	       "a second mapping gave back %u of %u bytes directly, %u through the bridge",
	       direct.round_trip, (unsigned)VKT_BYTES, (unsigned)value(5));

	fprintf(stderr, "direct : drawn inside %08x outside %08x image %016llx\n", direct.drawn_inside,
		direct.drawn_outside, (unsigned long long)direct.drawn_hash);
	fprintf(stderr, "bridged: drawn inside %08x outside %08x image %016llx\n", (uint32_t)value(6),
		(uint32_t)value(7), (unsigned long long)value(8));
	/* the triangle is the uniform's colour plus the push constant's:
	 * (0.5, 0.25, 0, 0.5) + (0.25, 0.25, 0.5, 0.5) = (0.75, 0.5, 0.5, 1) */
	px = (const uint8_t *)&direct.drawn_inside;
	EXPECT((px[0] == 0xbf || px[0] == 0xc0) && (px[1] == 0x7f || px[1] == 0x80) &&
	       (px[2] == 0x7f || px[2] == 0x80) && px[3] == 0xff,
	       "the direct run's triangle is %02x %02x %02x %02x, not the uniform plus the push constant",
	       px[0], px[1], px[2], px[3]);
	EXPECT(direct.drawn_outside == 0xff000000u, "the direct run drew outside the triangle (%08x)", direct.drawn_outside);
	EXPECT((uint32_t)value(6) == direct.drawn_inside, "the triangle's colour differs through the bridge");
	EXPECT((uint32_t)value(7) == direct.drawn_outside, "the pixel outside the triangle differs through the bridge");
	EXPECT(value(8) == direct.drawn_hash, "the drawn image differs through the bridge");

	/* The same draw with its uniform pushed, where the device can: the other
	 * uniform's colour, (0, 0.5, 0.25, 0.5) + (0.25, 0.25, 0.5, 0.5) =
	 * (0.25, 0.75, 0.75, 1). */
	if (direct.push_limit) {
		fprintf(stderr, "direct : pushed limit %u inside %08x image %016llx\n", direct.push_limit,
			direct.pushed_inside, (unsigned long long)direct.pushed_hash);
		fprintf(stderr, "bridged: pushed limit %u inside %08x image %016llx\n", (uint32_t)value(9),
			(uint32_t)value(10), (unsigned long long)value(11));
		px = (const uint8_t *)&direct.pushed_inside;
		EXPECT((px[0] == 0x3f || px[0] == 0x40) && (px[1] == 0xbf || px[1] == 0xc0) &&
		       (px[2] == 0xbf || px[2] == 0xc0) && px[3] == 0xff,
		       "the direct run's pushed triangle is %02x %02x %02x %02x, not the pushed uniform plus the push constant",
		       px[0], px[1], px[2], px[3]);
		EXPECT((uint32_t)value(9) == direct.push_limit, "how many descriptors may be pushed differs through the bridge");
		EXPECT((uint32_t)value(10) == direct.pushed_inside, "the pushed triangle's colour differs through the bridge");
		EXPECT(value(11) == direct.pushed_hash, "the image drawn with a pushed uniform differs through the bridge");
		/* Pushed through a template: the third colour, (0.5, 0, 0.5, 0.5) +
		 * (0.25, 0.25, 0.5, 0.5) = (0.75, 0.25, 1, 1). The bridge must
		 * translate the buffer's handle inside the template's data. */
		if (direct.templ_inside) {
			fprintf(stderr, "direct : template inside %08x image %016llx\n", direct.templ_inside,
				(unsigned long long)direct.templ_hash);
			fprintf(stderr, "bridged: template inside %08x image %016llx\n", (uint32_t)value(15),
				(unsigned long long)value(16));
			px = (const uint8_t *)&direct.templ_inside;
			EXPECT((px[0] == 0xbf || px[0] == 0xc0) && (px[1] == 0x3f || px[1] == 0x40) &&
			       px[2] == 0xff && px[3] == 0xff,
			       "the direct run's templated triangle is %02x %02x %02x %02x, not the third uniform plus the push constant",
			       px[0], px[1], px[2], px[3]);
			EXPECT((uint32_t)value(15) == direct.templ_inside, "the triangle pushed through a template differs through the bridge");
			EXPECT(value(16) == direct.templ_hash, "the image drawn with a template differs through the bridge");
		} else {
			fprintf(stderr, "NOT TESTED: this device has no VK_KHR_descriptor_update_template, so no template was used\n");
		}
	} else {
		fprintf(stderr, "NOT TESTED: this device has no VK_KHR_push_descriptor, so nothing was pushed\n");
		EXPECT(value(9) == 0, "the bridge offers push descriptors where the device has none");
	}

	/* Which of the commands with two names the device has, as the driver
	 * says and as the bridge says (vkt_name_pairs) */
	fprintf(stderr, "direct : commands with two names present %02x; bridged %02x\n",
		direct.names_present, (uint32_t)value(14));
	EXPECT((uint32_t)value(14) == direct.names_present,
	       "the bridge says the device has commands the driver does not (or not ones it does): %02x, driver %02x",
	       (uint32_t)value(14), direct.names_present);

	/* A command asked for by its extension's name, and called (issue 268 of
	 * chimera): the run itself stops at step 126 when the event stays unset. */
	if (direct.event_set)
		EXPECT(value(13) == 1, "an event set by a command in the queue is not set through the bridge");
	else
		fprintf(stderr, "NOT TESTED: this device has no VK_KHR_synchronization2, so no command was called by an extension's name\n");

	/* four calls in the run are wrong on purpose - a descriptor write with
	 * nothing to read, one to a set that does not exist, one with an image
	 * view the bridge never made, and a pipeline with a layout it never made
	 * - and they, and only they, must have been refused */
	/* the run resets its descriptor pool a thousand times and fills it again,
	 * and makes and destroys a semaphore a thousand times */
	fprintf(stderr, "bridged: %lu handle slots used\n", chimera_vk_host_handle_slots());
	EXPECT(chimera_vk_host_handle_slots() < 500, "the table of handles grew with every pool reset or destroyed object (%lu slots)",
	       chimera_vk_host_handle_slots());

	long last = -1;
	EXPECT(chimera_vk_host_refused(&last) == 4, "%lu calls were refused where four were meant to be (last opcode %ld)",
	       chimera_vk_host_refused(NULL), last);

	/* ---- a handle from before a load ---- */
	const uint64_t before = context_id();
	EXPECT(before != 0, "the context has no id");
	EXPECT(make_instance() == VK_SUCCESS, "the guest could not make an instance to keep");
	EXPECT(keep_card() == 1, "the guest could not keep the instance's card");
	EXPECT(ask_kept_card() != 0, "the kept card did not answer before the load");
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
	/* the same for a handle handed over by value to a command that returns
	 * nothing: refused and counted, with nothing written - and the host is
	 * still here to say so */
	const unsigned long refused_card = chimera_vk_host_refused(NULL);
	EXPECT(ask_kept_card() == 0, "a card from before the load answered");
	EXPECT(chimera_vk_host_refused(NULL) == refused_card + 1, "the stale card's call was not counted as refused");
	EXPECT(ask_fresh() == VK_SUCCESS, "the new context's own instance was refused");
	destroy_fresh();

	/* and the new context works, with the same result */
	const int failed_again = run();
	EXPECT(failed_again == 0, "after a load the run failed at step %d (VkResult %d)", failed_again, (int)(int64_t)value(1));
	EXPECT(value(3) == direct.image_hash && value(4) == pattern_hash && value(8) == direct.drawn_hash &&
	       value(11) == direct.pushed_hash,
	       "after a load the results differ");

	wbx_deactivate_host(g_host, &r);
	chimera_vk_host_shutdown();
	if (failures) {
		fprintf(stderr, "%d failed\n", failures);
		return 1;
	}
	fprintf(stderr, "vk bridge: ok\n");
	return 0;
}
