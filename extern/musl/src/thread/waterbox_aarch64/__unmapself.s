// munmap(base, size) then exit(0), on the waterbox call (syscall_arch.h);
// nothing of the stack being unmapped is touched in between
.global __unmapself
.type __unmapself,%function
__unmapself:
	mov x8, #11
	movz x16, #0x0080
	movk x16, #0x035f, lsl #32
	blr x16
	mov x0, #0
	mov x8, #60
	movz x16, #0x0080
	movk x16, #0x035f, lsl #32
	blr x16
	udf #0xf4
