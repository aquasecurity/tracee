#!/bin/bash

# Centralized Zig installation script for Tracee
# Supports Alpine Linux, Ubuntu/Debian, and CentOS/RHEL environments
#
# Zig is used only to build the syscaller integration-test helper
# (tests/integration/syscaller): a tiny, libc-free, single-threaded binary that
# triggers syscall-name events for the integration suite at the syscall-noise floor.

set -euo pipefail

# Source lib.sh for consistent logging and utilities
SCRIPT_DIR="${0%/*}"
__LIB_DIR="${SCRIPT_DIR}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# Configuration - single source of truth for Zig version.
# Pinned to 0.16: the syscaller source uses 0.16-specific std/build APIs (the Init entry model,
# the module-based build graph, the struct-literal asm clobbers) and the Makefile's .checkver_zig
# enforces this exact minor. When changing ZIG_VERSION, update the corresponding checksum files in:
#   scripts/installation/checksums/zig-x86_64-linux-${ZIG_VERSION}.tar.xz.sha256
#   scripts/installation/checksums/zig-aarch64-linux-${ZIG_VERSION}.tar.xz.sha256
# Get checksums from: https://ziglang.org/download/ (see index.json "shasum").
ZIG_VERSION="0.16.0"

install_zig() {
    info "Installing Zig ${ZIG_VERSION}"
    require_cmds curl tar xz

    # Detect architecture. Zig release tarballs use the raw uname arch names
    # (x86_64 / aarch64) - do NOT translate to amd64/arm64 like the Go installer.
    local arch
    arch=$(uname -m)
    case "${arch}" in
        x86_64 | aarch64) ;;
        *)
            die "Unsupported architecture: ${arch}"
            ;;
    esac

    # 0.16 tarballs are named zig-<arch>-linux-<ver>.tar.xz (arch/os order, swapped from older
    # zig-linux-<arch>-<ver>). The name must match the download URL and the checksum filename.
    local tarball_name="zig-${arch}-linux-${ZIG_VERSION}.tar.xz"
    local checksum_file="${SCRIPT_DIR}/checksums/${tarball_name}.sha256"
    local download_url="https://ziglang.org/download/${ZIG_VERSION}/${tarball_name}"

    # Check that the checksum file exists
    if [[ ! -f "${checksum_file}" ]]; then
        die "Zig checksum file not found: ${checksum_file}
Please create the checksum file with the SHA256 from https://ziglang.org/download/"
    fi

    # Remove any existing Zig installation
    rm -f /usr/bin/zig
    rm -rf /usr/local/zig

    # Download Zig tarball
    info "Downloading Zig ${ZIG_VERSION}..."
    if ! curl -fsSL -o "/tmp/${tarball_name}" "${download_url}"; then
        die "Failed to download Zig tarball from ${download_url}"
    fi

    # Verify the checksum before extraction
    if ! verify_sha256_checksum "/tmp/${tarball_name}" "${checksum_file}" "Zig ${ZIG_VERSION}"; then
        rm -f "/tmp/${tarball_name}"
        die "Aborting Zig installation due to checksum verification failure"
    fi

    # Checksum verified, proceed with extraction. The tarball's top-level dir is
    # versioned (zig-<arch>-linux-<ver>/), so strip it into a fixed /usr/local/zig.
    info "Extracting Zig to /usr/local/zig..."
    mkdir -p /usr/local/zig
    tar -C /usr/local/zig --strip-components=1 -xJf "/tmp/${tarball_name}"
    rm -f "/tmp/${tarball_name}"

    # Create symlink
    ln -s /usr/local/zig/zig /usr/bin/zig

    # Verify installation
    zig version
    info "Zig ${ZIG_VERSION} installed successfully"
}

install_zig
