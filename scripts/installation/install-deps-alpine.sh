#!/bin/sh

# Comprehensive dependency installation script for Tracee (Alpine Linux)

set -e

# Source lib.sh for consistent logging and utilities
SCRIPT_DIR="${0%/*}"
__LIB_DIR="${SCRIPT_DIR}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

info "Starting Tracee dependency installation on Alpine Linux"

install_base_packages() {
    info "Installing base packages"
    require_cmds apk

    apk add --no-cache \
        bash \
        build-base \
        sudo \
        coreutils \
        findutils \
        git \
        curl \
        rsync \
        make \
        gcc \
        musl-dev \
        linux-headers \
        elfutils-dev \
        libelf-static \
        zlib-static \
        zstd \
        zstd-static \
        libc6-compat \
        tar \
        ca-certificates \
        binutils-gold \
        bpftrace

    # Create symlinks for compatibility with tests expecting binaries in /usr/bin
    # BusyBox applets - link directly to busybox so applet name is detected correctly
    ln -sf /bin/busybox /usr/bin/uname
    ln -sf /bin/busybox /usr/bin/date
    ln -sf /bin/busybox /usr/bin/echo
    ln -sf /bin/bash /usr/bin/bash

    info "Base packages installed successfully"
}

install_golang() {
    bash "${SCRIPT_DIR}/install-golang.sh"
}

install_clang() {
    info "Installing Clang using centralized script"
    require_cmds bash

    # Call our existing Clang installation script
    bash "${SCRIPT_DIR}/install-clang.sh"

    info "Clang installation completed"
}

install_go_tools() {
    bash "${SCRIPT_DIR}/install-go-tools.sh"
}

verify_installation() {
    info "Verifying installation"

    require_cmds go gofmt clang clang-format staticcheck revive goimports-reviser errcheck govulncheck

    # Show versions
    info "Installation verification:"
    go version
    clang --version | head -n1
    clang-format --version | head -n1
    staticcheck -version

    info "All tools verified successfully"
}

# Stage modes let the container build environments (builder/Containerfile)
# install dependencies layer by layer; the default installs everything.
usage() {
    echo "usage: $0 [--base|--toolchain|--go-tools|--all]"
    exit 1
}

main() {
    info "=== Tracee Dependencies Installation ==="

    case "${1:---all}" in
        --base)
            install_base_packages
            ;;
        --toolchain)
            install_golang
            install_clang
            ;;
        --go-tools)
            install_go_tools
            ;;
        --all)
            install_base_packages
            install_golang
            install_clang
            install_go_tools
            verify_installation
            ;;
        *)
            usage
            ;;
    esac

    info "=== Tracee dependencies installation completed successfully! ==="
}

main "$@"
