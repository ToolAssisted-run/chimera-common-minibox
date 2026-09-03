#!/bin/sh
# Guest-image hygiene check: a .wbx must not touch %fs BY ACCIDENT.
#
# There are two kinds of guest, and the difference is whether the image
# declares thread-local storage of its own.
#
# A guest with NO PT_TLS segment (every C/C++ guest on the waterbox musl, which
# reaches its thread pointer through %gs) must never touch %fs at all. The
# sandbox leaves fs alone for such a guest, so on Linux an fs access silently
# reads the HOST thread's TLS block - it even appears to work, because glibc
# keeps its stack guard at fs:0x28 and the canary compares a host value with
# itself - and on Windows the fs base of a user thread is 0 and the same
# instruction kills the process. Both are host leaks.
#
# A guest WITH a PT_TLS segment (a Rust guest: std uses thread locals
# throughout) is a different animal. miniBox gives such a guest its own %fs
# around every entry and puts the host's back on the way out, so thread locals
# there are the guest's own memory and are expected. Rejecting them would mean
# rejecting Rust.
#
# How fs code sneaks in even with the right flags:
#   - thread_local variables (compile them out; the TLS symbol check below)
#   - __attribute__((target(...))) functions: gcc RESETS target flags there,
#     dropping -mstack-protector-guard=global and reverting the canary to
#     fs:0x28 (zstd's DYNAMIC_BMI2 bodies, libstdc++'s rdrand helpers).
#     -fno-stack-protector is the cure: -f flags survive target attributes.
#
# usage: check-wbx.sh <core.wbx>   (exits nonzero on any violation)
set -eu
wbx="$1"
[ -f "$wbx" ] || { echo "check-wbx: $wbx not found" >&2; exit 1; }

# Does the image declare TLS of its own? That is what miniBox itself keys the
# %fs swap on (mb_elf_has_tls), so the check asks exactly the same question.
has_tls_segment="$(readelf -lW "$wbx" 2>/dev/null | awk '$1 == "TLS" { print "yes"; exit }')"

if [ -n "$has_tls_segment" ]; then
	echo "check-wbx: $wbx declares PT_TLS; %fs is the guest's own and is handled by the host"
	exit 0
fi

tls="$(readelf -sW "$wbx" 2>/dev/null | awk '$4 == "TLS"' | head -5)"
if [ -n "$tls" ]; then
	echo "check-wbx: $wbx has TLS symbols but no PT_TLS segment - thread_local in guest code with nowhere to live:" >&2
	echo "$tls" >&2
	exit 1
fi

fscount="$(objdump -d "$wbx" 2>/dev/null | grep -c '%fs:' || true)"
if [ "$fscount" -ne 0 ]; then
	echo "check-wbx: $wbx contains $fscount %fs-relative accesses (host leak; fatal on Windows):" >&2
	objdump -d "$wbx" | awk '/^[0-9a-f]+ </{fn=$2} /%fs:/{print "  " fn}' | sort -u >&2
	exit 1
fi

echo "check-wbx: $wbx clean (no TLS symbols, no %fs accesses)"
