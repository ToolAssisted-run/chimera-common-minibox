#include <stdarg.h>
#include <stdint.h>
#include "pthread_impl.h"
#include "syscall.h"

/* wbx_clone(2000) on an aarch64 machine: (thread pointer, child sp, child pc,
 * child tid address, parent tid address, the pthread struct).
 *
 * The child starts at __wbx_child_start with the guest_syscall trampoline's
 * frame popped, so sp is the stack given here, holding {arg, fn}. The host
 * reads the thread's stack out of the pthread struct (words 12, 13) - on
 * aarch64 the thread pointer is past the struct (TP_ADJ), so the struct is
 * passed as well; x86-64's clone.s leaves the same pointer in that register. */
hidden void __wbx_child_start(void);
__asm__(
	".text\n"
	".type __wbx_child_start,%function\n"
	"__wbx_child_start:\n"
	"	ldp x0, x1, [sp], #16\n"   /* arg, fn */
	"	blr x1\n"
	"	mov x8, #60\n"             /* exit(the thread's answer) */
	"	movz x16, #0x0080\n"
	"	movk x16, #0x035f, lsl #32\n"
	"	blr x16\n"
	"	udf #0xf4\n"
);

int __clone(int (*fn)(void *), void *stack, int flags, void *arg, ...)
{
	va_list ap;
	va_start(ap, arg);
	pid_t *ptid = va_arg(ap, pid_t *);
	void *tls = va_arg(ap, void *);
	pid_t *ctid = va_arg(ap, pid_t *);
	va_end(ap);
	(void)flags;
	uintptr_t sp = ((uintptr_t)stack & -(uintptr_t)16) - 16;
	((void **)sp)[0] = arg;
	((void **)sp)[1] = (void *)fn;
	struct pthread *self = (struct pthread *)((char *)tls - sizeof(struct pthread));
	return __syscall(2000, tls, sp, __wbx_child_start, ctid, ptid, self);
}
