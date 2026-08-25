#!/bin/sh
# Guest-image hygiene check: a .wbx must never touch %fs.
#
# The sandbox does not virtualize the fs segment. On Linux a guest fs access
# silently reads the HOST thread's TLS block (it happens to work: glibc keeps
# its own stack-guard at fs:0x28, so canary checks compare a host value against
# itself); on Windows the fs base of a user thread is 0 and the same
# instruction kills the process. Both are host leaks; neither belongs in a
# deterministic guest.
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

tls="$(readelf -sW "$wbx" 2>/dev/null | awk '$4 == "TLS"' | head -5)"
if [ -n "$tls" ]; then
	echo "check-wbx: $wbx has TLS symbols (thread_local in guest code):" >&2
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
