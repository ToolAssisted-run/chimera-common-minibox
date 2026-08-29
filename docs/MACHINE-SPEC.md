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

All guests share one 64-bit layout. The guest image and every heap live in a
single aligned 4 GiB region (`start >> 32 == (end-1) >> 32`); construction fails
otherwise. Page size is 0x1000 (4096); all region bases and sizes are page
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
- On Windows, stack pages (RWStack) cannot use the fault handler (NT cannot
  dispatch an exception when [rsp] is unwritable), so they map PAGE_READWRITE |
  PAGE_GUARD; a guard trip is caught and returns continue-execution without
  taking the lock; dirtiness is recovered lazily by scanning VirtualQuery for
  cleared guard bits (`get_stack_dirty`), and RWStack snapshots are pre-captured
  at allocation and at seal. On Linux, RWStack is just R-until-written and goes
  through the normal handler; get_stack_dirty is a no-op.

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
3. Memory block seal: get_stack_dirty; for every dirty non-invisible page, clear
   dirty and set its snapshot to None (the live image becomes the baseline;
   Windows additionally pre-snapshots RWStack pages). Refresh protections (now
   all writable pages are mapped R/RX). Compute the block hash: SHA-256 of the
   block address range followed by, per page, a tag byte 1 (None), 2
   (ZeroFilled), or the 4096 snapshot bytes (Data). Mark sealed.

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
FileSystem: magic "FileSystem"; per mounted savestateable file a record (name
            magic, then class-specific state: readonly files store only the
            seek position and are hash-verified; writable files are illegal at
            save time); magic "FileSystemEnd"
u64    program_break
ElfLoader: magic "ElfLoader"; the ELF SHA-256 (hard-verified on load)
MemoryBlock: magic "ActivatedMemoryBlock"; the seal hash; the block AddressRange
            (start,size hard-verified); then two length-N byte arrays -
            page status (1 byte each) and page dirty (1 byte each); then, for
            each non-invisible dirty page in order, its 4096 bytes (read through
            the mirror)
GuestThreadSet: magic "GuestThreadSet"; thread states; magic "GuestThreadSet"
            (single-thread implementations: active_tid must be 1)
magic  "ˇsoHxoqɹǝʇɐMpǝʇɐʌᴉʇɔ∀"  (SAVE_END_MAGIC, upside-down "ActivatedWaterboxHost")
```

Load reconstructs each page from the (old_dirty, new_dirty) pair:
(false,false) nothing; (false,true) snapshot current then read 4096 from stream;
(true,false) restore baseline (ZeroFilled->zero, Data->memcpy, None->error);
(true,true) read 4096 from stream. Then set status, refresh protections.

Verification: ELF hash mismatch is a hard error; readonly-file hash and
name/order mismatches are hard errors; block address mismatch is a hard error;
block hash mismatch is a warning only (the reference does not fail on it - a
known soft spot). A failed load poisons the instance.

## 7. Syscall surface (observable)

The guest issues a syscall as `call [0x35f00000080]` with the number in rax and
SysV C argument order (rdi,rsi,rdx,rcx,r8,r9 - note arg4 is rcx, NOT r10 as in
the kernel ABI; the guest treats rbx, r12-r15 and all vector registers as
clobbered across the call). Return value in rax; errors are `-errno` with the
error threshold at `-4096`.

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
- **ioctl(16)**: returns 0 unconditionally.
- **read(0)/write(1)/readv(19)/writev(20)**: VFS I/O; iov entries with
  iov_base==0 are skipped.
- **open(2)/close(3)/lseek(8)/truncate(76)/ftruncate(77)**: VFS.
- **clock_gettime(228)**: writes tv_sec=1495889068, tv_nsec=0 regardless of the
  clock id; returns 0. (This constant is part of the spec.)
- **exit(60)**: thread exit (tid 1 exiting traps).
- **futex(202)**: WAIT/WAKE/REQUEUE/LOCK_PI/UNLOCK_PI with FUTEX_PRIVATE(128)
  masked; FIFO waiter queues; timeouts ignored; else ENOSYS.
- **wbx_clone(2000)**: the custom guest-thread spawn (see threading).
- **set_thread_area(205)** -> ENOSYS (musl handles in userspace).
- **set_tid_address(218)**, **gettid(186)**, **sched_yield(24)**,
  **nanosleep(35)/clock_nanosleep(230)** (treated as yields),
  **rt_sigprocmask(14)** -> 0, **getpid(39)/getppid(110)** -> 1.
- Everything else: trap to the debugger (breakpoint) then return ENOSYS. This
  forbids getrandom, gettimeofday/time, sockets, fork/execve, openat, arch_prctl
  from the guest, poll/select, and all other host-observing calls.

## 8. Virtual filesystem (observable)

A flat list of named in-memory files (no directories). Preloaded: /dev/stdin
(fd 0, empty reader, always 0 bytes), /dev/stdout (fd 1), /dev/stderr (fd 2),
these last two forwarding to the host console and non-unmountable; host write
errors are swallowed (never surfaced to the guest). Mounted files (via
wbx_mount_file) are readonly (SHA-256-bound to savestates) or writable
(transient; block savestating). One fd per file; opening an already-open file
-> EACCES; fd allocation is lowest-unused; close resets seek to 0; open checks
only O_ACCMODE. Fabricated stat: st_dev=1, st_ino=1, st_nlink=0, st_blksize=4096,
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

This is v1. Any change to an observable behavior above is a new machine-spec
version. Implementations declare which versions they implement; a movie recorded
under version N requires a host implementing version N. Non-observable host
internals (page tracking strategy, snapshot storage, threading scheduler data
structures) may change freely without a version bump as long as every byte in
sections 1-9 is preserved.
