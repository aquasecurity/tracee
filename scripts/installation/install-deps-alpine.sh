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

    apk update
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

check_docker() {
    info "Checking Docker availability"

    # Check if Docker is already installed
    if command -v docker > /dev/null 2>&1; then
        info "Docker already installed: $(docker --version)"
    else
        info "Docker not found. Installing from Alpine repositories..."
        apk add docker docker-cli-compose
        info "Docker installed successfully"
    fi
    
    # Add user to docker group if USER_NAME is set and not root
    if [ -n "${USER_NAME}" ] && [ "${USER_NAME}" != "root" ]; then
        if getent group docker >/dev/null 2>&1; then
            addgroup "${USER_NAME}" docker
            info "Added ${USER_NAME} to docker group"
        else
            info "Docker group not found, skipping group assignment"
        fi
    fi
}

verify_installation() {
    info "Verifying installation"

    # Check critical tools (Docker is optional)
    require_cmds go gofmt clang clang-format staticcheck revive goimports-reviser errcheck

    # Show versions
    info "Installation verification:"
    go version
    clang --version | head -n1
    clang-format --version | head -n1
    staticcheck -version

    # Check Docker availability (optional)
    if command -v docker > /dev/null 2>&1; then
        docker --version
    else
        info "Docker not available (will be provided by GitHub Actions)"
    fi

    info "All tools verified successfully"
}

main() {
    info "=== Tracee Dependencies Installation ==="

    install_base_packages
    install_golang
    install_clang
    install_go_tools
    check_docker
    verify_installation

    info "=== Tracee dependencies installation completed successfully! ==="
}

main "$@"
