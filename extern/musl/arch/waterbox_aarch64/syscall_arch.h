/* The waterbox syscall on an aarch64 machine: a plain call to the fixed
 * guest_syscall trampoline (0x35f00000080) with the number in x8 and the
 * arguments in x0-x5, as the kernel's svc takes them; the answer comes back in
 * x0. The trampoline keeps x29/x30 on the guest stack and nothing else, and a
 * syscall can switch guest threads, so - as on x86-64 - every other register,
 * the callee-saved ones included, is clobbered across it (the host zeroes the
 * scratch ones on the way back). */

#define __SYSCALL_LL_E(x) (x)
#define __SYSCALL_LL_O(x) (x)

#define __WBX_SYSCALL_CLOBBERS "x6", "x7", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x17", "x18", "x30", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "memory", "cc"

static __inline long __syscall0(long n)
{
	register long x8 __asm__("x8") = n;
	register long x16 __asm__("x16") = 0x35f00000080;
	register long x0 __asm__("x0") = 0;
	register long x1 __asm__("x1") = 0;
	register long x2 __asm__("x2") = 0;
	register long x3 __asm__("x3") = 0;
	register long x4 __asm__("x4") = 0;
	register long x5 __asm__("x5") = 0;
	__asm__ __volatile__ ("blr x16"
		: "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), "+r"(x8), "+r"(x16)
		:
		: __WBX_SYSCALL_CLOBBERS);
	return x0;
}

static __inline long __syscall1(long n, long a1)
{
	register long x8 __asm__("x8") = n;
	register long x16 __asm__("x16") = 0x35f00000080;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = 0;
	register long x2 __asm__("x2") = 0;
	register long x3 __asm__("x3") = 0;
	register long x4 __asm__("x4") = 0;
	register long x5 __asm__("x5") = 0;
	__asm__ __volatile__ ("blr x16"
		: "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), "+r"(x8), "+r"(x16)
		:
		: __WBX_SYSCALL_CLOBBERS);
	return x0;
}

static __inline long __syscall2(long n, long a1, long a2)
{
	register long x8 __asm__("x8") = n;
	register long x16 __asm__("x16") = 0x35f00000080;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = 0;
	register long x3 __asm__("x3") = 0;
	register long x4 __asm__("x4") = 0;
	register long x5 __asm__("x5") = 0;
	__asm__ __volatile__ ("blr x16"
		: "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), "+r"(x8), "+r"(x16)
		:
		: __WBX_SYSCALL_CLOBBERS);
	return x0;
}

static __inline long __syscall3(long n, long a1, long a2, long a3)
{
	register long x8 __asm__("x8") = n;
	register long x16 __asm__("x16") = 0x35f00000080;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = 0;
	register long x4 __asm__("x4") = 0;
	register long x5 __asm__("x5") = 0;
	__asm__ __volatile__ ("blr x16"
		: "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), "+r"(x8), "+r"(x16)
		:
		: __WBX_SYSCALL_CLOBBERS);
	return x0;
}

static __inline long __syscall4(long n, long a1, long a2, long a3, long a4)
{
	register long x8 __asm__("x8") = n;
	register long x16 __asm__("x16") = 0x35f00000080;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = 0;
	register long x5 __asm__("x5") = 0;
	__asm__ __volatile__ ("blr x16"
		: "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), "+r"(x8), "+r"(x16)
		:
		: __WBX_SYSCALL_CLOBBERS);
	return x0;
}

static __inline long __syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
	register long x8 __asm__("x8") = n;
	register long x16 __asm__("x16") = 0x35f00000080;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = a5;
	register long x5 __asm__("x5") = 0;
	__asm__ __volatile__ ("blr x16"
		: "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), "+r"(x8), "+r"(x16)
		:
		: __WBX_SYSCALL_CLOBBERS);
	return x0;
}

static __inline long __syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	register long x8 __asm__("x8") = n;
	register long x16 __asm__("x16") = 0x35f00000080;
	register long x0 __asm__("x0") = a1;
	register long x1 __asm__("x1") = a2;
	register long x2 __asm__("x2") = a3;
	register long x3 __asm__("x3") = a4;
	register long x4 __asm__("x4") = a5;
	register long x5 __asm__("x5") = a6;
	__asm__ __volatile__ ("blr x16"
		: "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), "+r"(x8), "+r"(x16)
		:
		: __WBX_SYSCALL_CLOBBERS);
	return x0;
}

#define IPC_64 0
