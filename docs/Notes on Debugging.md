# How to Debug Waterbox and Cores

Bring lots of tools, and lots of self loathing.

## Windows

### gdb

* Usually comes from mingw, or something
* Example script to attach to a running BizHawk instance:
	```
	#!/bin/bash
	PSLINE=$(eval "ps -W | grep EmuHawk")

	if [[ $PSLINE =~ [0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+([0-9]+) ]]; then
		gdb --pid=${BASH_REMATCH[1]}
	fi
	```
* Thinks we're in x86-32 mode because of the PE header on EmuHawk.exe.  We're not.
	You can put this in `~/.gdbinit` (or maybe add it to the startgdb script?)
	```
	set arch i386:x86-64
	```
* The waterbox files have DWARF information, which gdb can read.  If you build a waterbox core in debug mode,
	you even get full source level debugging.  With the new rust based waterboxhost, these symbol files should automatically
	be registered for you as waterboxhost hits a gdb hook.
	* The gdb hook is experimental, so be ready with `add-sym foobar.wbx` if needed.
* Has no way to understand first chance vs second chance exceptions.  Since lazystates was added, the cores now
	emit lots of benign SIGSEGVs as the waterboxhost discovers what memory space they use.  You can suppress these exceptions:
	```
	han SIGSEGV nos nopr
	```
	But if the real exception you're trying to break on is a SIGSEGV, this leaves you defenseless.
	You probably want to use the `no-dirty-detection` feature in waterboxhost to turn off these
	SIGSEGVs for some kinds of debugging.
* Also understands symbols for waterboxhost.dll, since that was actually built with MINGW.
* `b rust_panic` to examine rust unwinds before they explode your computer.
* Breakpoints on symbols in the wbx file just don't work a lot of the time.
	* This is the single worst part of modern waterbox debugging.  I have no idea what gdb is doing wrong.  It sees the wbx
		symbols and can print stack information and tell you what function you're in, and print globals, but `b some_emu_core_function`
		just doesn't get hit.  I think it might have something to do with how we map memory.  This worked in some previous
		waterbox editions, but I never got to the bottom.
	* Recompile cores with lots of `__asm__("int3")` in them?  Heh.

### windbg

* `!address`, `!vprot` are useful for examining VirtualQuery information.
* Can't read any symbols, which makes it mostly useless until you've narrowed things down heavily.
* Has more useful stack traces than gdb, as gdb usually can't see the stack outside DWARF land.
* Understands first and second chance exceptions.
	* `sxd av` will do exactly what we need for lazystate page mapping; break only when our handled decides not to handle it.
* Can give reasonable information on random WIN32 exceptions with `!analyze`

### OmniSharp

* Great visibility into C# exceptions, pretty worthless otherwise.

### General unwinding hazards

* Within the guest, DWARF unwinding information is available and libunwind is used.  Guest C++ programs can freely use exceptions,
	and Mednafen does so without issue.
	* Trying to unwind out of the guest stack will not work, so there needs to be a top level catch.
* SEH unwinds, either from C# or Rust code, while in a callback from guest code back to host code, will unwind fine, but they
	will skip right past the guest code.  This recovers the host system, but means that the guest is likely hosed as it
	had no chance to run any dtors.
* Any unwinding on a libco cothread will likely make me laugh.

## Linux

### gdb

* Only game in town here.
* Mono seems to use a lot of custom signals for... something.
	* This script will start gdb, ignore those signals, and start EmuHawk:
		```
		#!/bin/bash
		gdb -iex "han SIG35 nos" -iex "han SIG36 nos" --args mono ./EmuHawk.exe "$@"
		```
* Because you're actually in linux, beware function names: `b mmap` can mean the host libc's mmap, the rust implementation of the guest mmap,
	or the guest libc's mmap.
* Same general problem with intermittently functional guest breakpoints as Windows.  Heh.
* Same lazystate SIGSEGV problem (and same solutions) as Windows.
* Can see some mono symbols, which is sometimes useful.
* If you're looking for a pure core bug, this might be a better environment to test it on than Windows.  It depends.

## Guest thread pointers, and the `%fs` switches

Waterbox musl reaches its thread pointer through a patched `__set_thread_area`,
which writes `ctx->thread_area` and needs no segment register. A guest compiled
by LLVM does not: Rust emits local-exec TLS as plain `%fs:`-relative reads
(Ruffle's guest has over a thousand of them), so the sandbox has to point `%fs`
at the guest's thread area for the duration of guest code and put the host's
back before any host code runs. That swap is what these switches control.

Every run with such a guest prints one line naming what it decided:

	miniBox: guest declares TLS; %fs swap ON

The decision is gated on the guest ELF actually having a `PT_TLS` segment, and
on FSGSBASE being usable from user mode (`AT_HWCAP2` on Linux,
`PF_RDWRFSGSBASE_AVAILABLE` on Windows). Both halves appear in the reason.

* `MB_NO_FS_SWAP=1` forces it off. Use it to prove a bug is or is not the swap.
  Remember that `set` persists for the life of a Windows console; the startup
  line says `OFF (MB_NO_FS_SWAP set)` precisely so a stale variable is visible
  in a log rather than mistaken for a fresh failure.
* `MB_FORCE_FS_SWAP=1` forces it on where the OS declines to advertise fsbase.
  Testing only. It is how the swap path gets exercised on a machine that does
  not offer FSGSBASE at all, but see the warning about wine below.

Two hazards worth writing down, both of which cost real time:

* **The guest needs a thread pointer before its first instruction.** musl
  installs one early, but not early enough: `_start` and anything the loader
  touches before it can already read a thread local, and a `%fs` base of 0 turns
  that into a read of a small negative address. Linux hides this - `%fs` there
  is glibc's TCB, a real address, so the guest reads harmless nonsense and
  everything passes. On Windows nothing else uses `%fs` and the base is 0, so
  the same guest faults at `addr=fffffffffffffff8` before it does anything.
  `mb_context_init` therefore starts `thread_area` at a zeroed host page,
  pointed at from the middle so a TLS block's negative offsets stay inside it.
  musl replaces it within the first call.
* **wine is a false lead for anything `%fs`.** wine runs on Linux glibc, which
  does use `%fs`, so pointing `%fs` at the guest breaks wine itself rather than
  the guest. A `%fs` bug reproduced under wine is probably wine's. Test on real
  Windows or not at all.

* **Windows does not keep a user-mode FS base at all.** Not across a fault -
  across anything. Measured there with a five-line program: `wrfsbase`, then
  plain arithmetic with no fault, no syscall and no yield. The base survived
  `SwitchToThread`, was gone after `Sleep(1)`, and was gone after 47 ms and 16
  million iterations of pure computation - one scheduler quantum. Windows
  restores `%fs` for an x64 user thread believing the answer is always 0.

  So the loss has no event to hang a repair on, and a guest that reads a thread
  local often dies within a second of starting. The Windows handler therefore
  repairs on the way IN: guest code that faulted while `%fs` held anything but
  its thread pointer gets the pointer back and the instruction retried, which is
  safe because it faulted before it had any effect. A fault that is really the
  guest's own returns immediately with `%fs` correct and is handled normally,
  which bounds the retry to one pass. The way out still restores too.

  `MB_DROP_FS_ON_FAULT=1` simulates the way-OUT loss on a host that does not
  have the bug. It deliberately does not drive the way-in retry: it forces its
  answer unconditionally, and a forced answer there would retry for ever. That
  path can only be exercised on Windows.

Reading a Windows fault report: the `[veh] unhandled fault: addr=... rip=...`
line reports a GUEST address, so
`objdump -d --start-address=<rip> --stop-address=<rip+16> core.wbx` on the
packaged core names the exact instruction. That is usually faster than any
debugger, and it works from a log the user mailed in.

The line under the registers does the other half - WHO called it. A guest ELF is
ET_EXEC at a fixed base and a core package ships `core.wbx` unstripped, so the
`guest stack (addr2line -f -C -e core.wbx): +8:36f0... +40:36f0...` list is a
set of names away:
`addr2line -f -C -e core.wbx 0x36f01563547 0x36f012f9e0a`. Subtract one from
each before looking it up - a return address points at the instruction AFTER
the call, which for a call in the last statement of a function lands in the
next one. The offsets are from rsp, and only words that fall inside the ELF are
listed, so the list is a sieve and not a backtrace: a frame's return address
and a stale word from a call that has already returned look the same here.
Read it as candidates and check them against the code. It earned its keep on
chimera#110, where the faulting function was `__dynamic_cast` - a name that on
its own says nothing at all - and the words above it named
`GLGSRender::chimera_gl_teardown` and the container it was clearing.

## A fault the handler never gets to report

A guest fault normally ends in a diagnosis: `tripguard` says what address was
asked for, which block owns it and what state its page is in, to stderr and to
`minibox-diag.log`. Two ways that diagnosis never arrives, and both look
identical from outside - `Segmentation fault`, no file, nothing.

**A fault inside the fault handler.** `sa_mask` is `sigfillset`, so SIGSEGV is
blocked while the handler runs; a second one is force-delivered with the default
action and the process is gone before it can say a word. The handler now
notices, and prints both faults with `write(2)` before letting the process die
the way it would have. The usual cause is the handler calling something that is
not async-signal-safe - **stdio is the classic one**: a core whose own fault
callback used `fprintf` to explain that it was declining the fault killed the
host on that line, because musl's file lock reads a thread pointer that, inside
the handler, is not the guest's.

**A fault the kernel could not deliver at all.** Then no handler runs and there
is nothing to print. `MB_FAULT_TRAIL=<path>` is for that case: every fault
leaves four words - address, rip, rsp, direction - in a ring in that file
BEFORE anything else happens, so the last entries are where the process was when
it died. Three stores when on, nothing when off. Decode it as little-endian
`u64`s: `[0]` is the fault count, then 64 slots of four.

Linux only; on Windows the vectored handler reports the same things itself.

**A fault inside the fault handler, on Windows.** The same mistake there is
worse, not better. A vectored handler that faults is called AGAIN for its own
fault, at the same instruction, on the same stack, with no depth limit and no
second chance; it ends when the stack runs out. The crash note then says "stack
overflow in msvcrt.dll", which is true and names neither fault, and
`minibox-diag.log` holds one line about a real fault followed by hundreds of
identical lines about the handler faulting on its own diagnosis. That is
chimera#127 exactly: `mb_host_destroy` freed the host without taking back
`g_layout`, which points inside it, so `say_region` read a dead heap chunk the
next time anything at all faulted - and on Windows a freed chunk really is
gone.

Two rules came out of it. The handler gives up its pointers when the machine
that owns them is destroyed, `g_layout` as well as `mb_guest_ctx`. And the
REPORT does not re-enter: handling may nest (the guest's own fault handler runs
guest code, which can trip a clean page and fault again, and that must be
served), but a fault that arrives while a report is running is said once, in
one sentence, and passed straight on - because describing it is exactly what
just failed. `run_guest --handler-recursion-child` is the leg: it points the
layout at an address that is not there, faults, and counts the `[veh]` lines.
Two is right; 659 is the handler eating its own stack.

## What the guest said last

A guest that aborts has usually already said why - a Rust panic prints
"panicked at", a failed allocation names its size - but it said it on a stderr
that a GUI process does not have, so the reason was lost at exactly the moment it
was the whole diagnosis. miniBox now keeps the newest 16 KB the guest wrote to
stdout and stderr, in host memory and never in a savestate, and every path about
to end the process writes that tail into `minibox-diag.log` after its own
report: the unimplemented-syscall trap, and the unhandled-fault reports on both
hosts.

A guest that dies no longer takes the process with it (see "A guest that dies",
below), but what it said still matters: the death's one-line reason quotes what
the dying CALL wrote - output from earlier calls is not why this one died - and
the full tail still goes to the log.

## A guest that dies

A guest dies in ways that are nothing to do with the host: `abort()` (which musl
turns into `tkill(self, SIGABRT)`, syscall 200 - a Rust panic, a failed
allocation, an assertion), a `hlt` from musl's `a_crash()` when its heap check
fails, a wild pointer, `ud2`, a division by zero, `exit()`, a deadlock, or a
syscall the host does not provide. Each used to be a trap that ended the
frontend.

Every exported call now enters the guest through `guarded.S`, which leaves an
escape record on the host stack. A death is recorded (`mb_host_guest_death`),
the machine is marked dead, and control returns to that record - from host C
through `mb_guarded_escape_now`, or from a fault handler (SIGSEGV, SIGILL, SIGFPE
on Linux; the vectored handler on Windows) by rewriting the interrupted context.
The call returns 0. Every later call into the machine returns 0 and runs
nothing, until `wbx_load_state` revives it. `wbx_get_death` says whether it is
dead and why.

Still fatal: a fault in HOST code, a fault inside the fault handler, and a death
outside a guarded call (the guest's `_start`, a seal), where there is nothing to
return to. Those end the process as before, with their report in the log.

`run_guest` kills one host eight ways in turn (the conformance guest's `Abort`,
`Halt`, `Ud2`, `DivideByZero`, `WildWrite`, `ExitNow`, `UnknownSyscall`,
`Deadlock`) and checks each returns, names itself, refuses the next call, and
comes back exactly as saved after a state load - on Linux, under UBSan, and on
Windows.

## Two seals that disagree

A state carries the hash of the sealed baseline it was made against, and a load
refuses a state whose hash is not the block's ("state hash mismatch ... made by
another machine"). When one core, one configuration and one host refuse each
other's states across two processes, the two seals differ somewhere - and the
hash alone does not say where.

`MB_SEAL_DUMP=<file>` appends, at every seal, what the hash was taken over: for
each page its address, status and snapshot kind, and the page's bytes when it
kept a DATA snapshot. Seal twice, in two processes, and compare the files page by
page.

That is how issue #80 was found. PPSSPP's states were refused in every new
process on Windows and never on Linux. Of 341,677 pages the two dumps differed
in 2, both `MB_ST_RWSTACK` pages holding timer readings the boot had left below
the stack pointer. A Windows stack page written before the seal keeps a snapshot
(nothing reports its writes, so they are found by comparison), and the hash used
to take those bytes. It now takes such a page by its tag, as on Linux.
`test_stack_leftovers_are_not_identity` holds that line, and only the Windows run
can fail it.
