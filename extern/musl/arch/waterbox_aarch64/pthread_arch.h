/* aarch64's thread pointer, TPIDR_EL0, read directly: on an aarch64 machine
 * the host swaps it in for the guest (there is no spare register for the
 * x86-64 waterbox's gs:0x18 trick), so it is always the guest's own while
 * guest code runs. It is SET through the host (__set_thread_area). */
static inline struct pthread *__pthread_self()
{
	char *self;
	__asm__ ("mrs %0,tpidr_el0" : "=r"(self));
	return (void*)(self - sizeof(struct pthread));
}

#define TLS_ABOVE_TP
#define GAP_ABOVE_TP 16
#define TP_ADJ(p) ((char *)(p) + sizeof(struct pthread))

#define MC_PC pc
