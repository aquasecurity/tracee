#!/bin/sh

# Extract an uncompressed vmlinux ELF from a compressed kernel image (bzImage),
# which is what Firecracker requires. Inspired by the kernel tree's
# scripts/extract-vmlinux (Copyright 2009 Simon Horman, GPL-2.0), but the
# magic scan is reimplemented: the upstream `tr`-based trick is locale- and
# byte-fragile (it silently finds nothing for the zstd magic on a UTF-8 host),
# so we locate the compressed payload with a raw-byte fixed-string grep under
# LC_ALL=C instead. Handles whatever a distro generic kernel uses (Ubuntu and
# Fedora both ship zstd today). Prints vmlinux to stdout.
#
# usage: extract-vmlinux.sh <compressed-kernel-image>

set -e

# byte-wise, not codepoint-wise: the magics contain high bytes (0xb5, 0xfd, ...)
# that a UTF-8 locale mangles in grep/tr
export LC_ALL=C

img="${1:?usage: $0 <bzImage>}"

command -v readelf > /dev/null 2>&1 || {
    echo "extract-vmlinux: readelf required (binutils)" >&2
    exit 1
}

tmp=$(mktemp)
trap 'rm -f "${tmp}"' EXIT

# check_vmlinux: emit and exit if $1 is an ELF vmlinux
check_vmlinux() {
    readelf -h "$1" > /dev/null 2>&1 || return 1
    cat "$1"
    exit 0
}

# try_decompress <magic-printf-octal> <decompressor...>
#
# The magic is given as printf octal escapes and must be NUL-free (a shell
# variable cannot carry a NUL): use the leading NUL-free run of the real magic,
# which is still selective enough - a wrong hit just fails to decompress and is
# skipped. grep -abo -F reports every byte offset of the raw magic; we try each.
try_decompress() {
    # $1 IS the printf format (octal escapes to interpret into raw bytes)
    # shellcheck disable=SC2059
    raw=$(printf "$1")
    shift
    # each offset is a single integer token: word-splitting is intended
    # shellcheck disable=SC2013
    for pos in $(grep -abo -F "${raw}" "${img}" 2> /dev/null | cut -d: -f1); do
        tail -c "+$((pos + 1))" "${img}" 2> /dev/null | "$@" > "${tmp}" 2> /dev/null || true
        # exits 0 on success; the '|| true' is essential - without it a
        # false-positive magic hit returns non-zero as the loop's last command
        # and `set -e` aborts the whole script before the correct decompressor
        # (e.g. zstd after a stray gzip magic) is ever tried
        check_vmlinux "${tmp}" || true
    done
}

# already an ELF?
check_vmlinux "${img}" || true

# magic (NUL-free prefix) / decompressor, tried in this order
try_decompress '\037\213\010'          gunzip            # gzip  1f 8b 08
try_decompress '\375\067\172\130\132'  unxz              # xz    fd 37 7a 58 5a
try_decompress '\211\114\132\117'      lzop -d           # lzop  89 4c 5a 4f
try_decompress '\002\041\114\030'      lz4 -d            # lz4   02 21 4c 18
try_decompress '\050\265\057\375'      unzstd            # zstd  28 b5 2f fd

echo "extract-vmlinux: could not decompress ${img}" >&2
exit 1
