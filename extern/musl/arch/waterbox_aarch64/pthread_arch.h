/* An aarch64 machine's thread pointer is the word at 0x36ef0000000, not
 * TPIDR_EL0: macOS writes the CPU number into TPIDR_EL0 at every context
 * switch, so no value of the guest's survives there (miniBox MACHINE-SPEC,
 * "aarch64"). The host keeps the word; the guest only reads it, and SETS it
 * through the host (__set_thread_area). Code the compiler emits for thread
 * locals still says `mrs xN, tpidr_el0`, and the guest kit rewrites each of
 * those to a read of this word when the image is linked (wbx-tp-rewrite). */
static inline struct pthread *__pthread_self()
{
	char *self = *(char *const volatile *)0x36ef0000000ul;
	return (void*)(self - sizeof(struct pthread));
}

#define TLS_ABOVE_TP
#define GAP_ABOVE_TP 16
#define TP_ADJ(p) ((char *)(p) + sizeof(struct pthread))

#define MC_PC pc
