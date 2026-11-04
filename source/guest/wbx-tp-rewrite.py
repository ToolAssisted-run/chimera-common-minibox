#!/usr/bin/env python3
"""Point an aarch64 guest's thread-pointer reads at the machine's slot.

An aarch64 machine keeps the guest's thread pointer in the word at
0x36ef0000000, not in TPIDR_EL0 (MACHINE-SPEC, "aarch64"): macOS writes the CPU
number into TPIDR_EL0 at every context switch, so nothing the guest leaves
there survives. musl reads the slot itself, but the compiler knows only the
register: every thread local it touches starts with `mrs xN, tpidr_el0`.

So once the image is linked, each of those becomes a branch to a trampoline
of its own,

    adrp xN, 0x36ef0000000
    ldr  xN, [xN]
    b    <the instruction after the mrs>

which leaves xN holding exactly what the mrs would have - and changes nothing
else: no other register, no flags, no stack. The trampolines go in a segment
of their own appended to the image (section .wbx_tp), so nothing already
linked moves. An `mrs xzr, tpidr_el0` reads nothing and becomes a nop.

`msr tpidr_el0, xN` is refused: the guest sets its thread pointer through the
host (set_thread_area), and one written to the register would be lost.

Code is told from data by the image's mapping symbols ($x, $d) where it has
them, else every word of an executable section counts as code. An image
already rewritten (it has .wbx_tp) is left alone, so a build may run this
twice. An x86-64 image has nothing to rewrite.

usage: wbx-tp-rewrite.py <core.wbx> [<out.wbx>]   (in place without <out>)
       wbx-tp-rewrite.py -- <link command...>      (link, then rewrite its -o)
"""
import bisect
import os
import struct
import subprocess
import sys

TP_SLOT = 0x36EF0000000
EM_X86_64 = 62
EM_AARCH64 = 183
PT_LOAD = 1
PT_GNU_PROPERTY = 0x6474E553
PF_X, PF_R = 1, 4
SHT_PROGBITS, SHT_SYMTAB = 1, 2
SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4
SEGMENT_ALIGN = 0x10000          # the largest host page miniBox runs on
SECTION = ".wbx_tp"

MRS_TPIDR = 0xD53BD040           # mrs xN, tpidr_el0 (| N)
MSR_TPIDR = 0xD51BD040           # msr tpidr_el0, xN (| N)
NOP = 0xD503201F

EHDR = struct.Struct("<16sHHIQQQIHHHHHH")
PHDR = struct.Struct("<IIQQQQQQ")   # type, flags, offset, vaddr, paddr, filesz, memsz, align
SHDR = struct.Struct("<IIQQQQIIQQ")
SYM = struct.Struct("<IBBHQQ")


def fail(msg):
    sys.exit("wbx-tp-rewrite: " + msg)


def adrp(rd, pc, target):
    imm = (target >> 12) - (pc >> 12)
    if not -(1 << 20) <= imm < (1 << 20):
        return None
    imm &= (1 << 21) - 1
    return 0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | rd


def ldr_x(rt, rn):                          # ldr xT, [xN]
    return 0xF9400000 | (rn << 5) | rt


def branch(pc, target):                     # b target
    off = target - pc
    if off % 4 or not -(1 << 27) <= off < (1 << 27):
        return None
    return 0x14000000 | ((off >> 2) & 0x3FFFFFF)


def link_then_rewrite(command):
    """The second form: a guest link, and this right after it, as one step a
    build can name (meson's custom_target runs one command)."""
    if "-o" not in command or command.index("-o") + 1 >= len(command):
        fail("a link command with no -o: " + " ".join(command))
    out = command[command.index("-o") + 1]
    # a build-tree tool comes as a bare relative path (meson's "musl-gcc"),
    # which exec would look for on PATH
    if os.sep not in command[0] and os.path.isfile(command[0]):
        command = [os.path.abspath(command[0])] + command[1:]
    done = subprocess.run(command)
    if done.returncode != 0:
        sys.exit(done.returncode)
    main([sys.argv[0], out])


def main(argv):
    if len(argv) >= 2 and argv[1] == "--":
        link_then_rewrite(argv[2:])
        return
    if len(argv) not in (2, 3):
        sys.exit("\n".join(__doc__.strip().splitlines()[-2:]))
    src = argv[1]
    dst = argv[2] if len(argv) == 3 else src
    with open(src, "rb") as f:
        image = bytearray(f.read())
    name = src

    if len(image) < EHDR.size or image[:4] != b"\x7fELF" or image[4] != 2 or image[5] != 1:
        fail(f"{name}: not a little-endian ELF64 image")
    (ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
     e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = EHDR.unpack_from(image, 0)

    def write_out(data, what):
        if dst != src or what:
            with open(dst, "wb") as f:
                f.write(data)
        if what:
            print(f"wbx-tp-rewrite: {name}: {what}")

    if e_machine == EM_X86_64:
        write_out(image, None)
        return
    if e_machine != EM_AARCH64:
        fail(f"{name}: machine {e_machine} is neither x86-64 nor aarch64")
    if e_shentsize != SHDR.size or e_phentsize != PHDR.size:
        fail(f"{name}: unexpected header sizes")

    shdrs = [list(SHDR.unpack_from(image, e_shoff + i * SHDR.size)) for i in range(e_shnum)]
    phdrs = [list(PHDR.unpack_from(image, e_phoff + i * PHDR.size)) for i in range(e_phnum)]
    shstr = shdrs[e_shstrndx]
    shstrtab = bytes(image[shstr[4]:shstr[4] + shstr[5]])

    def sec_name(sh):
        end = shstrtab.index(b"\0", sh[0])
        return shstrtab[sh[0]:end].decode()

    code = [i for i, sh in enumerate(shdrs)
            if sh[1] == SHT_PROGBITS and sh[2] & SHF_ALLOC and sh[2] & SHF_EXECINSTR]

    # Data inside code: the AArch64 ELF ABI's mapping symbols mark where each
    # run of code ($x) and data ($d) starts, per section.
    marks = {i: [] for i in code}
    for sh in shdrs:
        if sh[1] != SHT_SYMTAB:
            continue
        strtab = shdrs[sh[6]]
        names = image[strtab[4]:strtab[4] + strtab[5]]
        for k in range(sh[5] // SYM.size):
            st_name, st_info, st_other, st_shndx, st_value, st_size = SYM.unpack_from(image, sh[4] + k * SYM.size)
            if st_shndx not in marks:
                continue
            end = names.index(b"\0", st_name)
            label = bytes(names[st_name:end])
            if label in (b"$x", b"$d") or label.startswith((b"$x.", b"$d.")):
                marks[st_shndx].append((st_value, label[1:2] == b"x"))

    for runs in marks.values():
        runs.sort()
    starts = {i: [start for start, _ in runs] for i, runs in marks.items()}

    def is_code(i, addr):
        k = bisect.bisect_right(starts[i], addr)   # the last mark at or below addr
        return k == 0 or marks[i][k - 1][1]

    already = any(sec_name(sh) == SECTION for sh in shdrs)

    sites, writes = [], []
    for i in code:
        sh = shdrs[i]
        addr, off, size = sh[3], sh[4], sh[5]
        for k in range(0, size - size % 4, 4):
            word = struct.unpack_from("<I", image, off + k)[0]
            top = word & ~0x1F
            if top != MRS_TPIDR and top != MSR_TPIDR:
                continue
            if not is_code(i, addr + k):
                continue
            if top == MSR_TPIDR:
                writes.append(addr + k)
            else:
                sites.append((addr + k, off + k, word & 0x1F))

    if writes:
        fail(f"{name}: writes TPIDR_EL0 at " + ", ".join(hex(a) for a in writes[:8])
             + " - an aarch64 guest sets its thread pointer through the host (set_thread_area)")
    if already:
        if sites:
            fail(f"{name}: has {SECTION} but still reads TPIDR_EL0 at " + ", ".join(hex(a) for a in sites[:8]))
        write_out(image, None)
        return
    if not sites:
        write_out(image, "reads no thread pointer; unchanged")
        return

    # The trampolines' segment: after everything the image loads, on its own
    # 64 KiB page, file offset congruent to the address as a loader wants.
    loads = [p for p in phdrs if p[0] == PT_LOAD]
    top_addr = max(p[3] + p[6] for p in loads)   # vaddr + memsz: past the .bss
    seg_addr = (top_addr + SEGMENT_ALIGN - 1) & ~(SEGMENT_ALIGN - 1)
    for p in loads:   # (a segment laid over the .bss would be zeroed by it, or zero it)
        if p[3] < seg_addr + 12 * len(sites) and seg_addr < p[3] + p[6]:
            fail(f"{name}: the trampolines at {seg_addr:#x} would overlap the segment at {p[3]:#x}")

    tramp = bytearray()
    for pc, foff, reg in sites:
        if reg == 31:                    # mrs xzr: reads nothing
            struct.pack_into("<I", image, foff, NOP)
            continue
        t = seg_addr + len(tramp)
        a = adrp(reg, t, TP_SLOT)
        back = branch(t + 8, pc + 4)
        there = branch(pc, t)
        if a is None or back is None or there is None:
            fail(f"{name}: the read at {pc:#x} is too far from the trampolines at {t:#x} "
                 f"(a branch reaches 128 MiB) or they from the slot (adrp reaches 4 GiB)")
        tramp += struct.pack("<III", a, ldr_x(reg, reg), back)
        struct.pack_into("<I", image, foff, there)
    if not tramp:
        write_out(image, f"{len(sites)} empty thread-pointer read(s) made nops")
        return

    # The program headers stay where they are and gain one entry: the guest
    # reads them from memory (musl finds its PT_TLS at __ehdr_start + e_phoff,
    # cxxglue its PT_LOADs and PT_GNU_EH_FRAME), so they must stay inside the
    # first segment. Where the linker left the rest of that page empty the
    # entry goes after them. Where it did not - binutils on a distribution
    # whose gcc marks objects for BTI puts .note.gnu.property there - the
    # PT_GNU_PROPERTY entry gives up its slot: it repeats the PT_NOTE entry
    # beside it for a kernel's sake, and nothing loads a guest but miniBox,
    # which reads neither.
    ph_end = e_phoff + (e_phnum + 1) * PHDR.size
    first = min(p for p in loads if p[2] == 0) if any(p[2] == 0 for p in loads) else None
    if first is None or ph_end > first[2] + first[5]:   # offset + filesz
        fail(f"{name}: its program headers are not inside its first segment")
    room = not any(image[e_phoff + e_phnum * PHDR.size:ph_end])
    for i, sh in enumerate(shdrs):
        if i and sh[1] != 8 and sh[5] and sh[4] < ph_end and e_phoff + e_phnum * PHDR.size < sh[4] + sh[5]:
            room = False
    if not room:
        spare = [i for i, p in enumerate(phdrs) if p[0] == PT_GNU_PROPERTY]
        if not spare:
            fail(f"{name}: no room after its program headers for one more, and no PT_GNU_PROPERTY to give way")
        del phdrs[spare[0]]

    # Append the trampolines, then a section-name table that names them and
    # the section headers - those two moved to the end whole, so nothing
    # already in the file changes place (nothing reads them from memory).
    def pad_to(align, congruent=0):
        while len(image) % align != congruent % align:
            image.append(0)

    pad_to(SEGMENT_ALIGN, seg_addr)
    seg_off = len(image)
    image += tramp

    pad_to(1)
    new_shstr_off = len(image)
    name_off = len(shstrtab)
    image += shstrtab + SECTION.encode() + b"\0"
    shstr[4], shstr[5] = new_shstr_off, len(shstrtab) + len(SECTION) + 1

    pad_to(8)
    new_shoff = len(image)
    shdrs.append([name_off, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, seg_addr, seg_off, len(tramp), 0, 0, 4, 0])
    for sh in shdrs:
        image += SHDR.pack(*sh)

    phdrs.append([PT_LOAD, PF_R | PF_X, seg_off, seg_addr, seg_addr, len(tramp), len(tramp), SEGMENT_ALIGN])
    for i, ph in enumerate(phdrs):
        PHDR.pack_into(image, e_phoff + i * PHDR.size, *ph)

    EHDR.pack_into(image, 0, ident, e_type, e_machine, e_version, e_entry, e_phoff, new_shoff, e_flags,
                   e_ehsize, e_phentsize, len(phdrs), e_shentsize, len(shdrs), e_shstrndx)
    write_out(image, f"{len(sites)} thread-pointer read(s) now read {TP_SLOT:#x} "
                     f"({len(tramp)} bytes of trampolines at {seg_addr:#x})")


if __name__ == "__main__":
    main(sys.argv)
