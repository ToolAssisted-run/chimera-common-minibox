/* The host half of the Vulkan bridge (see vk-bridge.h for what the bridge
 * is). One implementation, in miniBox, for everything that runs a guest: the
 * frontend's engine and a core's own test runner link this same file. */
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The callback a guest reaches the bridge through. It is entered from the
 * guest, which is sysv64 on every host. */
#if defined(_WIN32) && defined(__GNUC__)
#define VKB_GUEST_ABI __attribute__((sysv_abi))
#else
#define VKB_GUEST_ABI
#endif

/* Find the machine's Vulkan loader. 0 when there is one; otherwise the reason
 * in err. Nothing is created until a guest asks for an instance. */
int chimera_vk_host_init(char *err, int errlen);

/* Hand this to wbx_get_callback_addr. */
uintptr_t VKB_GUEST_ABI chimera_vk_host_dispatch(uintptr_t op, uintptr_t a, uintptr_t b,
                                                 uintptr_t c, uintptr_t d, uintptr_t e);

/* A savestate was loaded into the guest. Every object the guest's memory now
 * names belongs to another moment: all of them are destroyed, with the device
 * and the instance, and the context is a new one. */
void chimera_vk_host_state_loaded(void);

/* Destroy everything and let the loader go. */
void chimera_vk_host_shutdown(void);

/* The device calls are landing on; "" before a guest has made one. */
const char *chimera_vk_host_description(void);

/* How many calls were refused - a handle that named nothing, a command the
 * driver does not have - and the opcode of the last one. A run that ends with
 * this above zero drew something other than what it was asked to. */
unsigned long chimera_vk_host_refused(long *last_op);

#ifdef __cplusplus
}
#endif
