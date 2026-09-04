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

* **The base does not survive a Windows fault.** An exception is delivered by
  the kernel, and the user-mode FS base does not come back with the thread: the
  guest resumes with `%fs` at 0 and dies at its next thread-local read, far from
  the fault that broke it. The handlers therefore decide "is this guest code"
  from the faulting rip rather than from `rdfsbase()`, and reinstall the recorded
  base on the way out - a write of the value already there on a host that kept
  it. `MB_DROP_FS_ON_FAULT=1` simulates the loss on a host that does not have
  the bug, which is the only way to exercise the repair off Windows.

Reading a Windows fault report: the `[veh] unhandled fault: addr=... rip=...`
line reports a GUEST address, so
`objdump -d --start-address=<rip> --stop-address=<rip+16> core.wbx` on the
packaged core names the exact instruction. That is usually faster than any
debugger, and it works from a log the user mailed in.
