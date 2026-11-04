#include "pthread_impl.h"
#include "syscall.h"

/* On an aarch64 machine the thread pointer is a word the host keeps (see
 * pthread_arch.h), installed whenever guest code runs. So the guest does not
 * write it: it tells the host (set_thread_area, 205), which keeps it in the
 * context and installs it before returning here. */
int __set_thread_area(void *p)
{
	return __syscall(SYS_set_thread_area, p);
}
