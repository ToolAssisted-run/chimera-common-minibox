incdir=$1
libdir=$2
ldso=$3
arch=$4
# The flags every compile for the machine carries, whatever builds it. x86-64:
# no red zone (a dirty-tracking fault may land at any instruction). aarch64 has
# no red zone to begin with; it needs no return-address signing (keyed per
# process: a signed pointer in a savestate is a different pointer in the next
# process), no outline atomics (they ask the CPU what it has), and arithmetic
# that rounds as x86-64's does - no fused multiply-add, and a signed char.
# aarch64's long double is IEEE quad in software, so libc itself calls
# libgcc (__addtf3 and friends): libgcc goes around libc there, as gcc's own
# link does. x86-64's long double is the x87's, and libc needs nothing of it.
case "$arch" in
waterbox_aarch64) cc1_machine="-mbranch-protection=none -mno-outline-atomics -ffp-contract=off -fsigned-char"
	libgcc_spec="-lgcc" ;;
waterbox) cc1_machine="-mno-red-zone"
	libgcc_spec="" ;;
*) echo "musl-gcc.specs.sh: no machine for $arch: miniBox runs on x86-64 and aarch64 only" >&2
	exit 1 ;;
esac
cat <<EOF
%rename cpp_options old_cpp_options

*cpp_options:
-nostdinc -isystem $incdir -isystem include%s %(old_cpp_options)

*cc1:
%(cc1_cpu) $cc1_machine -nostdinc -isystem $incdir -isystem include%s

*link_libgcc:
-L$libdir -L .%s

*libgcc:
$libgcc_spec

*startfile:
%{!shared: $libdir/Scrt1.o} $libdir/crti.o

*endfile:
$libdir/crtn.o

*link:
-dynamic-linker $ldso -nostdlib %{shared:-shared} %{static:-static} %{rdynamic:-export-dynamic}

*esp_link:


*esp_options:


*esp_cpp_options:


EOF
