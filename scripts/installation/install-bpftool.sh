#!/bin/sh

# Install bpftool from the distro's package repository.
#
# This replaces the old btfhub source build, which compiled bpftool against a
# vmlinux.h dumped from the BUILD HOST's kernel - non-reproducible, and it
# breaks whenever the host kernel is newer than the pinned bpftool source.
# The distro package is prebuilt (host-agnostic) and pinned by the base image
# digest. Everything tracee needs (bpftool gen min_core_btf, btf dump) is
# available since bpftool 7.0.

set -e

# Source lib.sh for consistent logging and utilities
SCRIPT_DIR="${0%/*}"
__LIB_DIR="${SCRIPT_DIR}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

info "Installing bpftool from distro packages"

if [ -f /etc/alpine-release ]; then
    apk add --no-cache bpftool
elif command -v apt-get > /dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    if ! apt-get install -y --no-install-recommends bpftool; then
        # Ubuntu 24.04 has no standalone bpftool package: the real binary
        # ships in linux-tools-generic behind a kernel-version dispatch shim
        # that cannot work in a container - link the newest real binary
        apt-get install -y --no-install-recommends linux-tools-generic
        real=$(find /usr/lib -path '*linux-tools*' -name bpftool -type f 2> /dev/null | sort -V | tail -1)
        [ -n "${real}" ] || die "bpftool binary not found in linux-tools"
        ln -sf "${real}" /usr/local/sbin/bpftool
    fi
elif command -v dnf > /dev/null 2>&1; then
    dnf install -y bpftool
else
    die "Unsupported distro: no apk, apt-get or dnf found"
fi

bpftool version

info "bpftool installed successfully"
