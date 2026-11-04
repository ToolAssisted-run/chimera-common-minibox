// __syscall_cp_asm(&self->cancel, nr, u, v, w, x, y, z) for an aarch64
// waterbox machine: the cancellation check, then the waterbox call. A syscall
// may switch guest threads, which clobbers every register but x29/x30 (see
// syscall_arch.h), and this is called as a C function - so the callee-saved
// ones are kept here.

.global __cp_begin
.hidden __cp_begin
.global __cp_end
.hidden __cp_end
.global __cp_cancel
.hidden __cp_cancel
.hidden __cancel
.global __syscall_cp_asm
.hidden __syscall_cp_asm
.type __syscall_cp_asm,%function
__syscall_cp_asm:
	stp x29, x30, [sp, #-96]!
	stp x19, x20, [sp, #16]
	stp x21, x22, [sp, #32]
	stp x23, x24, [sp, #48]
	stp x25, x26, [sp, #64]
	stp x27, x28, [sp, #80]
	stp d8, d9, [sp, #-64]!
	stp d10, d11, [sp, #16]
	stp d12, d13, [sp, #32]
	stp d14, d15, [sp, #48]
__cp_begin:
	ldr w0, [x0]
	cbnz w0, 1f
	mov x8, x1
	mov x0, x2
	mov x1, x3
	mov x2, x4
	mov x3, x5
	mov x4, x6
	mov x5, x7
	movz x16, #0x0080
	movk x16, #0x035f, lsl #32
	blr x16
__cp_end:
	ldp d10, d11, [sp, #16]
	ldp d12, d13, [sp, #32]
	ldp d14, d15, [sp, #48]
	ldp d8, d9, [sp], #64
	ldp x19, x20, [sp, #16]
	ldp x21, x22, [sp, #32]
	ldp x23, x24, [sp, #48]
	ldp x25, x26, [sp, #64]
	ldp x27, x28, [sp, #80]
	ldp x29, x30, [sp], #96
	ret
1:
	ldp d10, d11, [sp, #16]
	ldp d12, d13, [sp, #32]
	ldp d14, d15, [sp, #48]
	ldp d8, d9, [sp], #64
	ldp x19, x20, [sp, #16]
	ldp x21, x22, [sp, #32]
	ldp x23, x24, [sp, #48]
	ldp x25, x26, [sp, #64]
	ldp x27, x28, [sp, #80]
	ldp x29, x30, [sp], #96
__cp_cancel:
	b __cancel
