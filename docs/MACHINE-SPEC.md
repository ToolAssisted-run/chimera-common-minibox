# The miniBox machine specification (v1)

This is the FROZEN, VERSIONED contract that defines the deterministic machine a
miniBox guest core runs on. Every host implementation (the C host in `host/`,
any future one) must
implement exactly this observable machine; any two implementations of spec
version N must be bit-identical for the same (guest image, mounted files, input
sequence). Movies record the machine-spec version; it is the third element of
Chimera's reproduction contract (movie + core package + machine-spec version).

"Observable" means: anything the guest can read, compute from, or have its
savestate depend on. Host-internal representation (how pages are tracked, how
snapshots are stored) is NOT observable and may differ between implementations,
as long as the guest-visible behavior and the savestate byte stream match.

This document is derived from BizHawk's waterbox, the original reference for
these behaviors; the authoritative contract, however, is this document, not
any implementation.

## 1. Address space

All guests share one 64-bit layout. The guest image and every heap live in one
contiguous block that starts on a 4 GiB boundary (`start & 0xffffffff == 0`)
and may span any number of 4 GiB regions (v2; v1 required the block to fit in
a single region). Construction fails otherwise. Page size is 0x1000 (4096); all region bases and sizes are page
aligned. `align_down(p) = p & ~0xfff`; `align_up(p) = ((p-1) | 0xfff) + 1`.

Two fixed absolute regions exist regardless of the guest:

| Address | Purpose |
|---|---|
| `0x35f00000000` | interop area base (ORG): stack-switch trampolines |
| `0x35f00000080` | `guest_syscall` - the syscall trampoline the guest calls |
| `0x35f00000100` | `call_guest_simple` entry |
| `0x35f00000200` | `call_guest_impl` entry |
| `0x35f00000300` | extcall thunk table (64 slots x 16 bytes) |
| `0x36f00000000` | conventional guest ELF load base (the guest is linked here) |

The interop area is a fixed 2088-byte machine-code blob (`context/interop.bin`,
assembled from `interop.s`); it is the SAME bytes in every implementation and is
mapped RX at ORG. It is not savestated (it never changes).

### Guest memory layout (WbxSysLayout)

Given the guest ELF's own address span `elf` (min..max of PT_LOAD vaddrs,
page-expanded), the layout is built by appending page-aligned regions in this
exact order (sizes from the host-supplied MemoryLayoutTemplate, except the two
fixed 1 MiB stacks):

```
elf          (from the ELF program headers, page-expanded)
main_thread  = 0x100000  (1 MiB)   guest main stack, grows down from its end
alt_thread   = 0x100000  (1 MiB)   guest alt/reentrancy stack
sbrk         = sbrk_size           serves brk(2)
sealed       = sealed_size         serves alloc_sealed(3)  (RO after seal)
invis        = invis_size          serves alloc_invisible(3) (never savestated)
plain        = plain_size          serves alloc_plain(3)   (savestated)
mmap         = mmap_size           arena for non-fixed mmap/mremap
```

This struct (8 {u64 start, u64 size} pairs, 128 bytes) is memcpy'd into the
guest's exported `__wbxsysinfo` symbol at load time if that symbol exists; its
size must equal 128 or load fails. The guest's emulibc reads it to learn its
heap arenas. It lives in the guest's `.invis` section, so it is not savestated.

## 2. Page model and protection

Each guest page has: an allocation status (Free, or Allocated with a protection
of None/R/RW/RX/RWX/RWStack), a dirty bit, and an invisible bit. These are
host-internal; what is observable is the *effective* access the guest gets and
what appears in savestates.

Effective access: an Allocated page grants exactly its protection (RWStack
behaves as RW to the guest). A Free page is inaccessible. RWStack exists only
so stacks can be dirty-tracked (see 4); to the guest it is RW.

The host tracks dirtiness by mapping logically-writable-but-clean pages as
read-only (RW->R, RWX->RX) and catching the first write via a fault handler
(see 4); this is invisible to the guest, which always observes full write
access to Allocated writable pages.

`page_info(i)` reports a byte per page for tooling (not part of guest-visible
behavior): 1=readable(=allocated), 2=writable, 4=executable, 0x10=stack,
0x20=allocated-but-unreadable(guard), 0x40=invisible, 0x80=dirty. Encoded:
Free=0, None=0x20, R=1, RW=3, RX=5, RWX=7, RWStack=0x13; |0x80 if dirty,
|0x40 if invisible.

## 3. ELF loading

The guest is a static, non-PIE ELF64 (`ET_EXEC`), linked at a fixed base
(conventionally 0x36f00000000). There is NO relocation processing of any kind;
vaddrs are used verbatim. Loading:

1. Compute `elf` span = [min, max) over PT_LOAD headers with p_vaddr != 0.
2. Build the layout (1); create the memory block; map the interop area.
3. Collect sections (name, addr, size) with sh_type != SHT_NOBITS, a real name,
   and sh_addr != 0. Collect exports: every symtab symbol with
   STV_DEFAULT visibility and STB_GLOBAL binding -> name->(value,size).
   Record the export named `__wbxsysinfo` specially.
4. If a `.invis` section exists, verify (page-expanded) that no other section
   partially overlaps its page range; then mark it invisible.
5. Mark the `invis` arena invisible.
6. For each PT_LOAD (p_vaddr != 0), page-expanded: mmap_fixed RW (no_replace
   false - RO segments may overlap on a page due to eh_frame_hdr), copy the
   segment's file bytes to its vaddr, then mprotect to the segment's real
   protection (R/RW/RX/RWX per the p_flags; W wins over X for RW).
7. If `__wbxsysinfo` was found, copy the 128-byte layout struct into it.
8. mmap_fixed main_thread RWStack (no_replace true); mprotect its low 4 pages
   (0x4000) to None as a guard; mark it invisible. Same for alt_thread.
9. Record the ELF's SHA-256 (whole file) for savestate binding.
10. Activate; call the entry point (`_start`) with call_guest_simple; deactivate.

Both guest STACKS are invisible - savestates are only taken with the guest
quiescent (between frames, main thread, empty stack of live data).

## 4. Dirty tracking (host-internal mechanism, observable only via savestates)

The essential guarantee: after seal (5), a savestate captures exactly the pages
that changed since the sealed baseline, and load restores the machine to the
saved point bit-exactly. How:

- A logically writable, non-dirty page is mapped read-only. The first guest
  write faults. The fault handler (Linux: SIGSEGV via sigaction with SA_SIGINFO
  | SA_ONSTACK, sigfillset mask, chaining to the previous handler for
  non-write/foreign faults; write-vs-read from ucontext REG_ERR & 2. Windows:
  vectored handler on STATUS_ACCESS_VIOLATION with write flag) finds the block
  containing the fault address, snapshots the pre-write page content if no
  snapshot is stored yet, marks the page dirty, and reprotects it to real
  writable. A fault on a non-writable page is re-thrown (not handled).
- On Windows, stack pages (RWStack) cannot use the fault handler at all: NT
  cannot dispatch an exception when [rsp] is unwritable, so a clean stack page
  kills the process instead of reporting itself. A guard page would be
  dispatchable, but a guard bit can also be cleared with no exception delivered,
  and then the write is invisible AND the page still says clean - measured, and
  it corrupts a history. So on Windows an RWStack page is mapped PAGE_READWRITE
  and nothing reports its writes; they are found by READING it. Its baseline is
  snapshotted when it is allocated and again at seal, and a copy (the shadow) is
  kept of what it held when the last delta was written. `dirty` is a comparison
  against the first, done before anything reads it (a savestate, a seal, a status
  change); the epoch's set is a comparison against the second, done when a delta
  is saved, which also refreshes the shadow where it differs. Both are exact, and
  both are stricter than a fault bit, which stays set when a page is written and
  then put back. The shadow is set when an epoch OPENS, as a hot page's is, so
  the epoch's comparison is the end of the frame against its start whatever
  happened in between - an anchor, a load, a delta apply, an epoch given up. A
  shadow left describing an older moment is NOT merely a frame behind: a stack
  that returns to that moment's bytes (a replay after a seek back does, exactly)
  is called unchanged, and the delta omits a page that changed. On Linux,
  RWStack is just R-until-written and goes through the normal handler.
- A guest therefore has to SAY where its stacks are, with MAP_STACK. One that
  runs on memory it merely allocated dies on Windows on its first push.

A `Snapshot` is a page's pre-change baseline content: None (the live memory IS
the baseline - a later write triggers snapshotting the pre-write bytes),
ZeroFilled, or Data(4096 bytes).

## 5. Seal

A one-shot operation after core init, before any savestate. Steps, in order:

1. Activate. Run the guest export `co_clean` if present (zeroes the host-thread
   register snapshot so it never enters savestates), then `ecl_seal` if present
   (emulibc mprotects the guest's own sealed heap to read-only).
2. ELF seal: mprotect to R every section whose name contains `.rel.ro`, or
   starts with `.got`, or equals `.init_array`/`.fini_array`/`.tbss`/`.sealed`.
3. Memory block seal: for every dirty non-invisible page, clear dirty and set
   its snapshot to None (the live image becomes the baseline; on Windows an
   RWStack page instead keeps a snapshot and stays dirty). Refresh protections (now
   all writable pages are mapped R/RX). Compute the block hash: SHA-256 of the
   block address range followed by, per page, a tag byte 1 (None), 2
   (ZeroFilled), or the 4096 snapshot bytes (Data). Mark sealed.

   A None page is named by its tag, not its bytes, so two boots that leave
   different bytes in the same pages seal to the same hash. Taking the bytes
   was measured (2026-10-18) and not done: six cores booted twice, in two
   processes, left the same bytes on Linux (up to 195 MB of such pages, up to
   112 ms to hash them), but on Windows Ruffle's two boots differed in 33
   pages. The differing words are host addresses: Windows handles a fault on
   the faulting thread's own stack, which is the guest's, and guest code later
   copies what that left there into its heap. Hashing the bytes would refuse
   such a core's states in every new process on Windows, as issue #80 did.

Savestate/load are illegal before seal.

## 6. Savestate format

Savestates are used for rewind/rerecord WITHIN a session; Chimera movies embed
inputs, not savestates, so a state never needs to move between host
implementations or across a spec version. Accordingly:

- What every implementation of a spec version MUST agree on (so behavior is
  identical): the magic strings, the ELF-hash and readonly-file-hash binding,
  the set of pages captured (exactly the non-invisible dirty pages), and the
  4096-byte page contents. These are the correctness-bearing parts.
- What is implementation-defined: the exact byte encoding of the per-page
  status and dirty arrays (the Rust reference emits its enum's in-memory bytes;
  the C port uses the explicit page_info encoding of section 2). Each host must
  round-trip its OWN states faithfully; cross-host state loading is not a v1
  requirement.

Differential validation therefore compares GUEST-OBSERVABLE state (memory
domains, video, audio) after identical input sequences and after save/load
round-trips - never raw savestate bytes.

The stream layout (structure fixed; integers little-endian; magic as raw UTF-8):

The stream is (all integers little-endian, magic strings as raw UTF-8 bytes):

```
magic  "ActivatedWaterboxHost_v1"
FileSystem: magic "FileSystem"; magic "FileSystemEnd" - nothing between
            them in this host (the reference put a record per mounted file
            there; the open files are in OpenFileTable1 below, and no file's
            bytes or hash are in a state)
u64    program_break
ElfLoader: magic "ElfLoader"; the ELF SHA-256 (hard-verified on load)
MemoryBlock: magic "ActivatedMemoryBlock"; the seal hash; the block AddressRange
            (start,size hard-verified); then two length-N byte arrays -
            page status (1 byte each) and page dirty (1 byte each); then, for
            each non-invisible dirty page in order, its 4096 bytes (read through
            the mirror)
GuestFpuState1: magic "GuestFpuState1"; u16 x87 control word; u32 MXCSR
            (section 9). A state written before 2026-10-18 has no such
            record; it loads with 0x037F and 0x1F80.
GuestThreadSet: magic "GuestThreadSet"; thread states; magic "GuestThreadSet"
            (single-thread implementations: active_tid must be 1)
OpenFileTable1: magic "OpenFileTable1"; u64 the getrandom stream's state;
            u32 count; per open descriptor, in descriptor order: i32 fd, u64
            position, u32 name length, the mounted file's name (2026-10-18).
            Deltas carry the same record after their thread set. A state or
            delta written before has no such record; it loads leaving the
            open descriptors and the stream as they are. So does one naming
            a file that is not mounted (a disc renamed since). (The FileSystem
            section above is written empty by this host: the open files are
            here.)
magic  "ˇsoHxoqɹǝʇɐMpǝʇɐʌᴉʇɔ∀"  (SAVE_END_MAGIC, upside-down "ActivatedWaterboxHost")
```

Load reconstructs each page from the (old_dirty, new_dirty) pair:
(false,false) nothing; (false,true) snapshot current then read 4096 from stream;
(true,false) restore baseline (ZeroFilled->zero, Data->memcpy, None->error);
(true,true) read 4096 from stream. Then set status, refresh protections.

Verification: ELF hash mismatch is a hard error; block address mismatch is a
hard error; a file the open-file table names that is not mounted leaves the
open descriptors as they are (above);
block hash mismatch is a hard error too (the reference only warns, a known
soft spot there): a state of another sealed baseline is refused before any
memory moves. A load refused before any memory moved (the magics, the ELF
hash, the block's hash and address) leaves the machine as it was; a load that
fails after that has a mix of two machines, and poisons the instance: it is
dead, as after a crash, until a state loads (2026-10-18).

## 7. Syscall surface (observable)

The guest issues a syscall as `call [0x35f00000080]` with the number in rax and
SysV C argument order (rdi,rsi,rdx,rcx,r8,r9 - note arg4 is rcx, NOT r10 as in
the kernel ABI; musl's stub for cancellable calls, used once a core links
pthread_cancel, put it in r10 until the kit of 2026-10-18; the guest treats
rbx, r12-r15 and all vector registers as clobbered across the call). Return
value in rax; errors are `-errno` with the error threshold at `-4096`.
Nothing of the host comes back in the other
registers: rcx, rdx, rsi, rdi, r8-r11 and xmm0-15 read zero after the call
(the same at the other two ways into the guest, section 9). Not a new version:
those registers held host values before, which no movie can depend on.

Implemented syscalls and their EXACT semantics:

- **mmap(9)**: requires MAP_ANONYMOUS (else EOPNOTSUPP); rejects flags & 0xf00
  (else EOPNOTSUPP); MAP_STACK (0x20000) with prot RW upgrades to RWStack, with
  any other prot -> EINVAL; MAP_FIXED_NOREPLACE (0x100000) sets no_replace.
  addr==0 -> place best-fit in the mmap arena; addr!=0 -> fixed at addr (may be
  anywhere in the block, not just the arena), no_replace -> EEXIST if any target
  page is not Free. size 0 -> EINVAL. Returns the address.
- **mremap(25)**: addr!=0 -> in-place only: grow requires following pages Free
  (else EEXIST) and the original fully allocated (else EINVAL); shrink munmaps
  the tail. Returns the (unchanged) address. (The move path is unreachable in
  the reference; MREMAP_MAYMOVE is never examined.)
- **mprotect(10)**: any Free page in range -> ENOMEM; else set protection.
- **munmap(11)**: any Free page in range -> EINVAL; else snapshot-if-needed,
  zero the pages (through the mirror), undirty pages whose baseline was
  ZeroFilled, set Free.
- **madvise(28)**: MADV_DONTNEED(4) same as munmap but keeps the pages allocated
  (advise_only); everything else returns 0.
- **brk(12)**: arena = sbrk. Unaligned addr, or addr < arena.start -> return old
  break (addr==0 prints an init message). addr > arena.end -> print a failure
  message and return old break (NO error). addr > old -> mmap_fixed [old,addr)
  RW, set break=addr. else return old.
- **stat(4)/fstat(5)**: VFS stat (see 8).
- **ioctl(16)**: returns 0. Nothing is a terminal and nothing is waiting, and
  what a guest reads back is written (2026-10-18): TIOCGWINSZ a zero window
  size (8 bytes), TCGETS zero termios (36 bytes), FIONREAD 0; EFAULT when that
  memory is not the guest's to write. Any other request writes nothing.
- **read(0)/write(1)/readv(19)/writev(20)**: VFS I/O; iov entries with
  iov_base==0 are skipped.
- **pread64(17)**: reads at an offset and leaves the descriptor's position
  alone (pwrite64, its twin, is in the v2.2 list below).
- **open(2)/close(3)/lseek(8)/truncate(76)/ftruncate(77)**: VFS.
- **openat(257)/newfstatat(262)**: open and stat, for the directory AT_FDCWD
  (-100) only; any other directory descriptor is EBADF (the namespace is
  flat, section 8).
- **dup(32)**: a second descriptor on the same file (section 8).
- **readlink(89)/readlinkat(267)**: nothing is a link and there is no /proc:
  EINVAL for a name that is mounted, ENOENT for one that is not. Nothing is
  written to the buffer.
- **fcntl(72)**: F_GETFD and F_GETFL answer 0; F_SETFD and F_SETFL are
  accepted and change nothing (there is no exec and no non-blocking mode);
  anything else is EINVAL.
- **sync(162)** returns 0; **fsync(74)/fdatasync(75)/syncfs(306)** return 0
  for an open descriptor and EBADF otherwise (the files live in host memory).
- **getrandom(318)**: fills the buffer from a fixed-seed splitmix64 stream
  that starts the same in every host and is saved in states (section 6); a
  buffer the guest does not own is EFAULT.
- **prctl(157)**: PR_SET_NAME (15) is accepted and ignored; anything else is
  EINVAL.
- **tkill(200)/tgkill(234)**: signal 0 answers whether the thread exists
  (0 or ESRCH); any other signal is the guest's death ("the core aborted"
  for SIGABRT). **exit_group(231)** is the guest's death too, with its
  status.
- **getuid(102)/geteuid(107)/getgid(104)/getegid(108)**: 1000.
- **sched_setaffinity(203)** returns 0; **sched_getaffinity(204)** writes a
  zero mask (up to 4096 bytes) and returns 8; a size under 8 or a null mask
  is EINVAL.
- **clock_gettime(228)**: writes the clock's start, tv_sec=1495889068,
  tv_nsec=0 unless the host was told another (below), regardless of the clock
  id; returns 0. (This start is part of the spec.) A host may be told another
  start before the guest first runs (`wbx_set_clock_start`, 2026-10-24,
  chimera#366): a whole second from 1970 to 2200-01-01, the same for every run
  of a machine, so a movie still replays.
- **sysinfo(99)**: zero-fills the 112-byte struct, then totalram = 1 GiB and
  freeram = 512 MiB; returns 0. mem_unit is 1, at offset 104 - for a core
  built with guest kit revision 1 or later. A core with no revision gets the
  old answer: the 1 written as a uint32 at offset 100, the top half of
  freehigh, so it reads mem_unit = 0 and freehigh = 4 GiB (see "Guest kit
  revisions").
- **exit(60)**: thread exit (tid 1 exiting traps).
- **futex(202)**: WAIT/WAKE/REQUEUE/LOCK_PI/UNLOCK_PI with FUTEX_PRIVATE(128)
  masked; FIFO waiter queues; timeouts ignored; else ENOSYS.
- **wbx_clone(2000)**: the custom guest-thread spawn (see threading).
- **set_thread_area(205)** -> ENOSYS (musl handles in userspace).
- **set_tid_address(218)**, **gettid(186)**, **sched_yield(24)**,
  **nanosleep(35)/clock_nanosleep(230)** (treated as yields),
  **rt_sigprocmask(14)** -> 0 with the old mask written as empty (nothing is
  delivered, so nothing is blocked; EFAULT for a mask the guest cannot use,
  EINVAL for a size over 128; 2026-10-18), **getpid(39)/getppid(110)** -> 1.
- Everything else is the guest's death, named ("the core asked for system
  call N ..., which the sandbox does not provide"): gettimeofday/time, fork/execve, arch_prctl,
  poll/select and every other host-observing call. Sockets and pipes are
  answered with a refusal instead (v2.2, below).

## 8. Virtual filesystem (observable)

A flat list of named in-memory files (no directories). Preloaded: /dev/stdin
(fd 0, empty reader, always 0 bytes), /dev/stdout (fd 1), /dev/stderr (fd 2),
these last two forwarding to the host console and non-unmountable; host write
errors are swallowed (never surfaced to the guest). Mounted files (via
wbx_mount_file) are read-only or writable. A read-only file may be open many
times at once, each descriptor with its own position starting at 0; a
writable file is open once at a time (a second open is EACCES). dup gives a
new descriptor on the same read-only file with its own position, starting
where the old one is (POSIX shares one; no caller needs that); dup of a
writable file is EACCES. fd allocation is lowest-unused; open checks only
O_ACCMODE. The open descriptors and their positions are in states (section
6, OpenFileTable1); a writable file's bytes are not, and stay as they are
across a load, so a core keeps data it writes in its own memory instead
(Chimera mounts every file read-only). The answers for a descriptor that
is not open, for seeking a stream and for a seek past the end depend on the
guest kit's revision ("Guest kit revisions", revision 2). Fabricated stat: st_dev=1, st_ino=1, st_nlink=0, st_blksize=4096,
S_IFREG if seekable else S_IFIFO, constant timestamps (1262304000000 s,
500000000 ns).

File-set determinism rules: every savestateable file must exist in every
savestate or in none; all savestateable files added in the same order every run;
save/load require no writable files mounted and the identical readonly file set.

## 9. Host<->guest transitions (observable via stability of stored pointers)

- Host->guest: call_guest_simple (0-arg entries: _start, co_clean, ecl_seal) or
  a per-entry call-in thunk. The thunk swaps rsp to the guest stack, publishes
  the Context at [gs:0x18], preserves/restores host TIB fields, supports two
  levels of reentrancy (guest->host->guest) via the alt stack pair.
- Guest->host callbacks: 64 fixed-address slot thunks at 0x35f00000300 +
  slot*16. A host callback registered in slot N is ALWAYS reachable by the guest
  at that fixed address, regardless of where the host library loaded - so a
  function-pointer value stored in savestated guest memory is stable across
  runs. This slot indirection is mandatory for any host pointer the guest keeps.
- All boundary-crossing functions are SysV ABI, at most 6 integer/pointer args,
  no floats or by-value structs.
- On entering a guest export, and on returning from a host callback, r10 and
  xmm0-15 read zero (after a callback also rcx, rdx, rsi, rdi, r8, r9 and r11;
  rax is the result). A guest that spills a register it never set - a varargs
  prologue spills xmm0-7 - must not find a host address in it. On entering a
  guest export the callee-saved rbx, rbp and r12-r15 read zero too
  (2026-10-18): a guest prologue or a cothread switch saves them into memory
  a state carries, and they held the host's pointers, different every run.
- Floating-point control words (2026-10-18): the x87 control word and MXCSR
  are part of the machine. A guest starts with 0x037F (64-bit precision,
  round to nearest, exceptions masked) and 0x1F80, whatever thread calls in
  (Windows starts its threads at 0x027F, 53-bit precision; Linux at 0x037F;
  a MinGW program such as chimera-run.exe sets 0x037F itself). The guest's
  are loaded on every way into guest code (an export, _start and the other
  0-arg entries, the return from a syscall or a host callback) and kept on
  every way out; what the guest sets stays with the guest, and is saved in
  states (section 6). Syscalls and host callbacks run with the words the host
  had when the call came in. Guest threads share one set, as before.
  This applies to every core, old and new. Every test script, chimera-run on
  both systems and the interface on Linux already ran guests at
  0x037F/0x1F80; what changed is the interface on Windows, which ran them at
  0x027F (and, after a guest changed its MXCSR, the host thread kept the
  guest's).
- TLS: the guest's pthread_self reads [gs:0x18] slot 0 (Context.thread_area).
  The host installs a gs base (Windows: TEB SubSystemTib field; Linux:
  arch_prctl ARCH_SET_GS to a 4-word thread-local block, only if gs is
  currently 0).

## 10. Determinism invariants a guest must uphold (documented, not enforced)

- The post-init (post-seal) memory image must be byte-identical every run: no
  host addresses, ASLR values, uninitialized-but-semantically-used bytes, or
  entropy in savestated memory.
- Host pointers stored in guest memory must come from callback slots (9).
- alloc_invisible/ECL_INVISIBLE memory is not savestated - use only for
  write-then-read-within-a-frame scratch.
- alloc_sealed/ECL_SEALED memory is read-only after seal.
- Nothing may depend on real time, randomness, the host environment, argv (the
  guest sees argv={"waterbox"}, env={WATERBOX=1}, empty auxv; main() is never
  called - init runs in .init_array and exported Init functions), or host files
  not mounted through the VFS.
- One guest thread runs at a time; guest atomics are non-atomic (single-thread
  assumption); any syscall is a potential thread-switch/state-restore point.

## Versioning

This is v2 (v1 + the multi-region block of section 1). Any change to an observable behavior above is a new machine-spec
version. Implementations declare which versions they implement; a movie recorded
under version N requires a host implementing version N. Non-observable host
internals (page tracking strategy, snapshot storage, threading scheduler data
structures) may change freely without a version bump as long as every byte in
sections 1-9 is preserved.

## Guest fault forwarding (spec v2.1)

A guest may protect pages of its own block (mprotect to read-only or
no-access) and rely on the first access to tell it so: an emulator's texture
cache watches guest memory that way. If the guest exports

    int GuestFaultHandler(uint64_t addr, uint64_t is_write)   (guest ABI)

the host resolves it at activation and calls it, on the faulting thread, for a
fault at an address inside the block whose page the guest protected below what
it could have (no-access, or read-only on a write). A nonzero return means the
guest changed the protection and the access is retried; zero, or no export, is
an unhandled fault as before. Faults on tracked clean pages (dirty-page
tracking) and on free pages are never the guest's. The handler runs on the
faulting thread's own stack, below the 128-byte red zone of the code that
faulted, and every register, the flags and the vector state of that code are
given back before the access is retried. It may itself fault on a tracked
clean page - its own thread locals, held by an epoch - and that fault is
served as any other; a fault it does not handle is the guest's death, as
anywhere in guest code. It may also make system calls that switch to another
guest thread, which may fault and run the handler in turn.

Windows calls the handler from its exception handler, which already runs on
the faulting thread's stack. Linux used to call it from the SIGSEGV handler,
on the host's alternate signal stack, and a handler that switched threads left
its frames there for the next fault to overwrite (2026-10-18). Since then the
signal handler points the thread at a trampoline in the host (guarded.S) and
returns; the trampoline saves the registers and the vector state (xsave),
calls the handler and restores them. A guest thread's stack needs room for
that frame (the vector state is 512 bytes to a few KiB, by processor); a fault
on a stack without it is the guest's death.

The fault can also be taken by host code: a system call whose answer the host
writes into guest memory (clock_gettime's result, a Vulkan command's output)
into a page the guest protected. The thread is outside the guest then, and the
handler is entered the way any call from the host is, through the guest-entry
thunk, so that its own system calls (unprotecting the page) work. Before
2026-10-15 it was called directly in that case too, and its first system call
ended the process (Chimera issue 280). Not observable to a guest that handles
its faults: it is now called where it used to kill the host.

A frontend that only READS guest memory - its memory tools, between frames,
on a thread of its own - does not go through the guest's view at all
(2026-10-18). Read there, a page the guest protected faults, the handler runs
on the frontend's thread, and a handler that writes memory (RPCS3's texture
cache writes the picture back) changes the machine: a movie could play
differently with a memory search open. `wbx_guest_read_view` hands it a
pointer to the same bytes through the block's mirror, which never faults; a
page the guest gave back reads as zeros there. A page of a lazy block (Windows,
over 4 GiB) with no memory behind it yet is given memory in the mirror alone
and reads zero, and a piece of such a block that a read view points into is
never given back to the OS (below). Writes still go through the guest's view,
where dirty tracking sees them.

On Windows a lazy block is made of 16 MiB pieces, each its own section, and
both of its views are built of them on reserved address space (2026-10-18):
a page of a view of a section cannot be given back on its own, so before,
memory a guest freed in a lazy block stayed taken until the block was. A
piece whose pages are all Free goes back to the OS when they become so
(unless a page in it is compared every frame, or invisible), and is made
again, empty, when the guest maps there next. Not observable to a guest:
Free pages read as zeros either way. MB_NO_PIECES set in the environment, or
a Windows without placeholders (before Windows 10 1803), keeps one section.

## A broken guest ends the machine, not the host (2026-10-18)

None of this changes what a working guest sees; it changes what a broken one
can do to the process that hosts it.

- The guest's start-up code (_start, its static constructors) and its seal
  (co_clean, ecl_seal) run under the same guarded call as an export. A guest
  that dies there is refused with the reason (wbx_create_host and wbx_seal
  answer an error) instead of trapping.
- A fault whose instruction is outside the guest's memory while the thread is
  inside a guest call (the gs block's context slot is set) is the guest's: a
  call through a null or wild function pointer is the guest's death.
- A callback slot the host never registered answers with the guest's death,
  "a host callback that was never registered", instead of jumping to 0.
- Every system call that reads or writes guest memory first asks whether the
  host may: inside the guest's memory, every page allocated and with the
  access needed, or protected below it by a guest that exports
  GuestFaultHandler. Otherwise it answers EFAULT, as Linux does. A read is
  checked for the bytes it will actually write.
- The OS refusing a protection change a tracked write needs (on Linux,
  vm.max_map_count) is the guest's death with that reason.
- A load that fails after it replaced memory poisons the machine (section 6).
- Not done: on Windows a guest stack that overflows into its guard page still
  ends the process. Windows builds the exception record on that same stack,
  and its dispatcher and the handler need more room than a guard page has.

## Stopping a guest that does not come back (2026-10-19, additive)

A frontend can end a guest call that has run too long from another thread.
Nothing changes for a guest that is never stopped.

- `wbx_stop_from_here(obj)` is called on the thread that will make the guest
  calls (once, and again if that thread changes). It installs what the stop
  needs: on Linux a signal handler for `SIGRTMAX - 3`, on Windows a handle to
  the thread.
- `wbx_stop_guest(obj, why)` from any thread asks the call running now to end
  as the guest's death, with `why` as the reason. The call answers as for any
  death: an error, and the machine ends. Where the guest is decides when:
  - in its own code: at once. On Linux the signal sends the thread out of the
    call; on Windows the thread is suspended, sent out and resumed.
  - in its own fault handler (GuestFaultHandler, for a fault its code took):
    at once, as in its own code. On Windows that handler runs inside the
    host's fault handler, so the thread is sent to a trap, and the trap
    leaves every handler frame from inside it (2026-10-24, chimera#363:
    RPCS3's texture cache waits in there, and a wait that never ended could
    not be stopped on Windows).
  - in a system call or a host callback: when it next makes a system call
    (every system call checks for a stop first).
  - in host code that never returns to the guest (a GPU call that waits for
    ever, the host's own work on a fault): not stopped. The frontend asks
    again.
  - asked on the thread running the call (from inside a host callback):
    at the guest's next system call.

  A stop is carried out only if the guest has not worked since it was asked
  for (the count below has not moved); otherwise it is dropped, and the
  frontend asks again if the guest gets stuck after all. A driver call that
  took long and came back is not a stuck guest.
- `wbx_stop_cancel(obj)` takes back a stop that was asked for but not yet
  carried out, for a call that ended by itself in between. A stop is never
  carried into the next call after a cancel.
- `wbx_guest_activity(obj)` answers a count of the guest's system calls,
  leaving out the ones a waiting or polling loop makes: sched_yield,
  clock_gettime, nanosleep, clock_nanosleep, futex, gettid and getpid. A
  frontend reads it as a sign of life: a guest whose count moves is working
  (RPCS3 compiling a game's code with LLVM makes a frame take 90 seconds),
  one whose count stands still is spinning or only waiting.
- `wbx_count_work_from(obj, counter)` adds a count the frontend keeps of its
  own work for the guest (its callbacks: a GPU driver call, a compile cache)
  into that count. The frontend adds 1 after each piece of work. The counter
  must outlive the host; NULL takes it away.

Tested by `conformance-stop` (`run_guest --stop`), on Linux and on Windows:
a guest spinning in its own code and one spinning on sched_yield are each
stopped from a second thread (on Linux the second with the stop's signal
blocked, so the check at a system call is what ends it); a stop asked for
before a call and cancelled ends nothing; the count moves for getppid and
not for yields; and a stop asked from inside a host callback ends the guest
at its next yield, unless the frontend counted work after the ask, when the
call ends by itself. `threads` (`run_threads`), on Linux and on Windows: a
guest looping inside its own fault handler is stopped from a second thread,
twice, and the machine runs again after a state load.

On Linux the stop's signal handler puts the host's `%fs` back before it runs
any host code, as the fault handler does, when the signal came in while a
guest that keeps its own `%fs` (it declares thread locals) was running: host
code reads its own thread's variables through `%fs`. Read through the
guest's, the stop was never carried out in a test guest and crashed in the C
library's `realloc` with xemu (chimera#330). Tested by `foreign-signal`'s
second part: its guest, which has thread locals, is stopped while it spins,
the call ends dead with the stop's reason, and the host's thread locals and
allocator are the host's afterwards. Without the change the spin never
ended.

## Answered instead of fatal (spec v2.2, additive)

These calls used to stop the machine (section 7's "everything else" rule),
which no working movie can depend on. Since v2.2 they get an answer and the
machine runs on:

- **rt_sigaction(13)**: returns 0; install accepted, never delivered (there
  is no signal delivery in-guest). A non-null `oldact` is written as the
  default action (all 32 bytes zero: SIG_DFL, no flags, empty mask); an
  `act` or `oldact` the guest does not own is EFAULT.
- **pipe(22)/pipe2(293)**: return ENOSYS (no pipes in-guest; a caller that
  needs one must cope with ENOSYS, as musl's posix_spawn does).
- **getrusage(98)**: zero-fills 144 bytes at the rusage pointer and returns
  0 (no resource usage is observable in-guest); a pointer the guest does not
  own is EFAULT.
- **wbx_clone(2000)** with `thread_area == 0`: returns EINVAL (a NULL area is
  a foreign clone convention, not the musl pthread struct whose words 12,13
  are stack_end/size; refused instead of faulting the host on pthread[12]).
- **pwrite64(18)** (2026-10-07, additive in the same way: it used to stop
  the machine): writes `count` bytes at `offset` of a writable mounted file
  and leaves the descriptor's position alone; an offset past the end is
  allowed and the gap reads as zeros. A descriptor that is not open, or not
  writable, is EBADF; stdout and stderr are ESPIPE; a buffer the guest does
  not own is EFAULT. pread64(17) has been there since v2.
- **socket(41)** (2026-10-08, additive in the same way): returns
  EAFNOSUPPORT for every family. There is no network in-guest and none will
  be offered; a caller that probes for one is told so and runs on. The
  first refusal of a run is noted in the diagnostic log.

## Virtual time (spec v3, opt-in)

A guest declares v3 by exporting a `uint32_t __wbx_machine_spec` holding 3,
read at load the way `__wbxsysinfo` is. No symbol (or a 2) means v2, and every
v2 behaviour above is unchanged, bit for bit - including the thread-state
format. A value the host does not implement refuses the load with a clear
message. There is deliberately no other clock input: no environment variable
reaches the machine, and no frontend-driven advance exists. A v3 guest that
wants frame-paced time calls `clock_nanosleep(frame_ns)` once per frame; the
policy stays inside the core, and the advance is part of the guest's own
instruction stream.

- **Clock**: starts at the clock's start (tv_sec=1495889068, tv_nsec=0
  unless the host was told another, whatever the clock id). Absolute times
  given to clock_nanosleep and futex are on the same scale, past that start.
  Every `clock_gettime` advances it by the tick, 1000 ns, then yields
  (below). The tick is a constant written here, not a
  knob: two runs of the same movie advance identically.
- **Thread switches**: a clock read yields after ticking, and a futex wake
  yields after waking. Reason: a thread spinning on the clock (or a waker
  that never sleeps) must hand the others a chance to run; without the yield
  a spinner starves every waiter it was waiting for. With one runnable thread
  the yield is a no-op returning the same value.
- **nanosleep(35)**: advances the clock by exactly the requested relative
  duration, then yields once. Negative or out-of-range requests are EINVAL,
  an unreadable pointer EFAULT, as on Linux (same for clock_nanosleep).
- **clock_nanosleep(230)**: relative requests behave as nanosleep; with
  TIMER_ABSTIME the clock advances to the absolute target when it is ahead of
  now, else advances nothing. Absolute means the clock's own scale (the
  readings it returns, starting at the constant above). The `rem` out-param
  is zeroed.
- **Futex timeouts**: WAIT takes a relative timeout, WAIT_BITSET an absolute
  one (same scale), as a µs-precise struct timespec in guest memory; NULL
  waits forever, as in v2. Negative or out-of-range fields are EINVAL, an
  unreadable pointer EFAULT, as on Linux. A waiter whose deadline arrives
  returns ETIMEDOUT (Linux errno 110).
- **Expiry order**: earliest deadline first; ties broken by park order (FIFO).
  Expiry is eager: after every clock advance, all waiters whose deadline has
  passed are woken with ETIMEDOUT before the next thread runs.
- **Nothing runnable**: when every thread is parked and at least one has a
  deadline, the clock fast-forwards to the earliest deadline and expiry runs
  as above. When every waiter has no timeout, the machine stops, as in v2.
- **Already-expired wait**: parking is skipped; the call costs one tick and
  returns ETIMEDOUT. (A zero-timeout spin therefore advances the clock
  instead of livelocking it: time passes while you spin, 1 us per call.)
  From guest kit revision 2 it then yields, as a clock read does.
- **sched_yield(24)**: from guest kit revision 2, a yield by the only
  runnable thread while another waits with a timeout costs one tick, so a
  thread that spins on yields alone still lets that timeout come.
- **Huge times**: from guest kit revision 2, a timespec or a deadline too
  large for the clock saturates at the clock's largest value (the v2
  constant plus the clock must fit in 64 bits), as Linux saturates at
  KTIME_MAX. Before, the nanoseconds wrapped round, and a sleep of the
  largest time there is ran the clock backwards.
- **mmap**: a bare hint (addr != 0, neither MAP_FIXED nor
  MAP_FIXED_NOREPLACE) is honoured when those pages are Free, and the call is
  placed best-fit otherwise. (v2 maps every bare hint fixed at the address.)
  MAP_FIXED maps at the address, discarding overlap, in both versions;
  MAP_FIXED_NOREPLACE keeps today's EEXIST rule in both. Discarding differs
  in what the overlap then holds: under v3, pages in the range that were
  already allocated come back zero-filled, as on Linux (each is zeroed and
  undirtied exactly as MADV_DONTNEED does; Free pages in the range are simply
  mapped). A runtime that decommits with `mmap(PROT_NONE, MAP_FIXED)` and
  recommits with `mmap(RW, MAP_FIXED)` relies on this. Under v2 the overlap
  keeps its bytes and only its protection changes. brk growth and the loader
  only ever map Free pages, so neither is affected.
- **mremap**: without MREMAP_MAYMOVE (1) the in-place rule is v2's (EEXIST
  when blocked). With MAYMOVE the mapping relocates to a best-fit free range
  (contents copied, old range freed) and returns the new address.
  MAYMOVE|FIXED is EINVAL (no fixed-target moves).
- **O_TRUNC**: on open of a writable regular mount with write access,
  truncates it to zero length first. (Streams cannot be truncated; O_TRUNC on
  one is ignored. O_TRUNC without write access is EACCES.)
- **Thread-state format v3**: magic `"GuestThreadSe3"`, then the clock (u64
  ns past the v2 constant), then exactly the v2 body, then per-thread
  deadlines (u64 ns absolute, 0 for none) in tid order. v3 guests only ever
  write and read this format. v2 guests keep the v1/v2 format byte for byte:
  no clock, no deadlines, magic `"GuestThreadSet"`.

## Guest kit revisions (2026-10-15)

A machine-spec version is chosen by the core (`__wbx_machine_spec`) and
changes how the machine behaves. A guest kit revision is narrower: it lets the
host correct an answer that was wrong after cores had shipped, without
changing the answer for those cores, so their movies replay as recorded.

The guest kit's `emulibc.c`, which every core links, exports
`uint32_t __wbx_kit_revision`, read at load the way `__wbx_machine_spec` is.
A core rebuilt with the kit therefore declares its revision without doing
anything; a core built before has no symbol and is revision 0. A symbol
pointing outside the guest's memory refuses the load.

- **Revision 1**: sysinfo's mem_unit is written at offset 104, where it
  belongs (section 7). Revision 0 keeps the write at offset 100.
- **Revision 2** (2026-10-18): the file answers are Linux's. A descriptor
  that is not open is EBADF for read, write, readv, writev, lseek, fstat
  and ftruncate (before: ENOENT, or EINVAL for lseek); seeking a stream is
  ESPIPE (before: EINVAL); a seek past a file's end is allowed, a read or
  pread there is end of file (0), and a write there fills the gap with zeros
  (before: EINVAL). Under v3, the virtual-time rules marked revision 2 in
  "Virtual time" apply.

The revision is independent of the machine-spec version: v2 and v3 cores alike
get the corrected answers once rebuilt. A rebuilt core is a new package, with
its own hash, so a project pinned to the old package keeps the old answers.

