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
# An archive or a single object has no segments and no linked %fs story of its
# own; only the red-zone rule below applies to it.
has_tls_segment=""
if ! readelf -hW "$wbx" 2>/dev/null | grep -q 'Type:.*EXEC'; then
	has_tls_segment="skip"
fi
[ "$has_tls_segment" = "skip" ] || has_tls_segment="$(readelf -lW "$wbx" 2>/dev/null | awk '$1 == "TLS" { print "yes"; exit }')"

if [ "$has_tls_segment" = "yes" ]; then
	echo "check-wbx: $wbx declares PT_TLS; %fs is the guest's own and is handled by the host"
	is_rust_style=1
fi

tls=""
[ "$has_tls_segment" = "" ] && tls="$(readelf -sW "$wbx" 2>/dev/null | awk '$4 == "TLS"' | head -5)"
if [ -n "$tls" ]; then
	echo "check-wbx: $wbx has TLS symbols but no PT_TLS segment - thread_local in guest code with nowhere to live:" >&2
	echo "$tls" >&2
	exit 1
fi

fscount=0
[ "$has_tls_segment" = "" ] && fscount="$(objdump -d "$wbx" 2>/dev/null | grep -c '%fs:' || true)"
if [ "$fscount" -ne 0 ]; then
	echo "check-wbx: $wbx contains $fscount %fs-relative accesses (host leak; fatal on Windows):" >&2
	objdump -d "$wbx" | awk '/^[0-9a-f]+ </{fn=$2} /%fs:/{print "  " fn}' | sort -u >&2
	exit 1
fi

# ---- the red zone ----------------------------------------------------------
# A guest may be interrupted by a dirty-tracking fault at any instruction, and
# on Windows the exception is delivered onto the guest's own stack, where the
# bytes below rsp do not survive it (miniBox docs/RED-ZONE.md: a leaf function
# that had spilled its limits there read them back as zeros, and the machine
# parted from Linux). So no guest code may keep anything below rsp: every
# object is built with -mno-red-zone (the musl-gcc specs carry it), and this
# is the check that a stray object, archive or hand-written routine did not
# slip past that. The rule is zero memory operands with a negative
# displacement from rsp, reported by symbol; the only exceptions are named in
# red-zone-allowlist.txt, each with the reason it is safe.
#
# This also runs on an archive (.a) or object (.o): the sysroot's own
# libraries are checked the same way.
allow="$(dirname "$0")/red-zone-allowlist.txt"
redzone="$(objdump -d --no-show-raw-insn "$wbx" 2>/dev/null \
	| awk -v allow="$allow" '
		BEGIN { while ((getline line < allow) > 0) { sub(/#.*/, "", line); gsub(/^[ \t]+|[ \t]+$/, "", line); if (line != "") ok[line] = 1 } }
		/^[0-9a-f]+ <.*>:$/ { fn = $2; sub(/^</, "", fn); sub(/>:$/, "", fn); next }
		# lea is address arithmetic, not a memory access: "lea -0x8(%rsp),%rsp"
		# IS the stack allocation, and "lea -0x1000(%rsp),%rax" is how a
		# variable-length array is set up. Neither keeps anything below rsp.
		/^ *[0-9a-f]+:\tlea |\tlea    / { next }
		# Only the unambiguous form, "-disp(%rsp)". An INDEXED operand such as
		# -0x8(%rsp,%rax,8) resolves above %rsp for any nonzero index and
		# cannot be judged without running the code, so counting it would
		# report compiler-generated frame indexing as a violation.
		/-0x[0-9a-f]+\(%rsp\)/ { if (!(fn in ok)) hits[fn]++ }
		END { for (f in hits) printf "  %6d  %s\n", hits[f], f }' \
	| sort -rn)"
if [ -n "$redzone" ]; then
	total="$(echo "$redzone" | awk '{ s += $1 } END { print s }')"
	echo "check-wbx: $wbx has $total memory operands below rsp (red zone) - guest code must be built with -mno-red-zone:" >&2
	echo "$redzone" | head -40 >&2
	[ "$(echo "$redzone" | wc -l)" -gt 40 ] && echo "  ... $(echo "$redzone" | wc -l) symbols in all" >&2
	exit 1
fi

echo "check-wbx: $wbx clean (no TLS symbols, no %fs accesses, nothing below rsp)"
