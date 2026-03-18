#!/bin/bash

# Centralized Go installation script for Tracee
# Supports Alpine Linux, Ubuntu/Debian, and CentOS/RHEL environments

set -euo pipefail

# Source lib.sh for consistent logging and utilities
SCRIPT_DIR="${0%/*}"
__LIB_DIR="${SCRIPT_DIR}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# Configuration - single source of truth for Go version
# When changing GOLANG_VERSION, update the corresponding checksum files in:
#   scripts/installation/checksums/go${GOLANG_VERSION}.linux-amd64.tar.gz.sha256
#   scripts/installation/checksums/go${GOLANG_VERSION}.linux-arm64.tar.gz.sha256
# Get checksums from: https://go.dev/dl/ (click "Show checksum" for each file)
GOLANG_VERSION="1.26.1"

install_golang() {
    info "Installing Go ${GOLANG_VERSION}"
    require_cmds curl tar

    # Detect architecture for Go download
    local arch
    arch=$(uname -m)
    local goarch
    case "${arch}" in
        x86_64) goarch="amd64" ;;
        aarch64) goarch="arm64" ;;
        *)
            die "Unsupported architecture: ${arch}"
            ;;
    esac

    local tarball_name="go${GOLANG_VERSION}.linux-${goarch}.tar.gz"
    local checksum_file="${SCRIPT_DIR}/checksums/${tarball_name}.sha256"
    local download_url="https://go.dev/dl/${tarball_name}"

    # Check that the checksum file exists
    if [[ ! -f "${checksum_file}" ]]; then
        die "Go checksum file not found: ${checksum_file}
Please create the checksum file with the SHA256 from https://go.dev/dl/"
    fi

    # Remove any existing Go installation
    rm -f /usr/bin/go /usr/bin/gofmt
    rm -rf /usr/local/go

    # Download Go tarball
    info "Downloading Go ${GOLANG_VERSION}..."
    if ! curl -fsSL -o "/tmp/${tarball_name}" "${download_url}"; then
        die "Failed to download Go tarball from ${download_url}"
    fi

    # Verify the checksum before extraction
    if ! verify_sha256_checksum "/tmp/${tarball_name}" "${checksum_file}" "Go ${GOLANG_VERSION}"; then
        rm -f "/tmp/${tarball_name}"
        die "Aborting Go installation due to checksum verification failure"
    fi

    # Checksum verified, proceed with extraction
    info "Extracting Go to /usr/local..."
    tar -C /usr/local -xzf "/tmp/${tarball_name}"
    rm -f "/tmp/${tarball_name}"

    # Create symlinks
    ln -s /usr/local/go/bin/go /usr/bin/go
    ln -s /usr/local/go/bin/gofmt /usr/bin/gofmt

    # Verify installation
    go version
    info "Go ${GOLANG_VERSION} installed successfully"
}

install_golang
