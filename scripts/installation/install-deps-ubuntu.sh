#!/bin/bash

# Comprehensive dependency installation script for Tracee (Ubuntu/Debian)
# For use in Vagrant VMs and Ubuntu-based environments

set -euo pipefail

# Source lib.sh for consistent logging and utilities
SCRIPT_DIR="${0%/*}"
__LIB_DIR="${SCRIPT_DIR}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

info "Starting Tracee dependency installation on Ubuntu/Debian"

wait_for_apt_locks() {
    info "Waiting for apt locks to be released..."
    while sudo fuser /var/lib/dpkg/lock-frontend > /dev/null 2>&1 || sudo fuser /var/lib/apt/lists/lock > /dev/null 2>&1; do
        sleep 1
    done
}

install_base_packages() {
    info "Installing base packages"
    require_cmds apt-get

    wait_for_apt_locks
    apt-get update
    apt-get install -y \
        bsdutils \
        build-essential \
        pkgconf \
        zlib1g-dev \
        libelf-dev \
        libzstd-dev \
        protobuf-compiler \
        curl \
        gnupg \
        tar \
        git \
        make \
        ca-certificates \
        wget \
        linux-tools-common \
        iputils-ping \
        netcat-openbsd \
        bpftrace

    info "Base packages installed successfully"
}

install_golang() {
    "${SCRIPT_DIR}/install-golang.sh"
}

install_clang() {
    info "Installing Clang using centralized script"
    require_cmds bash

    # Call our existing Clang installation script
    bash "${SCRIPT_DIR}/install-clang.sh"

    info "Clang installation completed"
}

install_go_tools() {
    "${SCRIPT_DIR}/install-go-tools.sh"
}

install_docker() {
    info "Installing Docker"
    require_cmds apt-get gpg

    # Install lsb-release for Ubuntu codename detection
    apt-get update
    apt-get install -y lsb-release

    # Add Docker GPG key (from local vendored copy) and repository
    rm -f /usr/share/keyrings/docker-archive-keyring.gpg
    gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg < "${SCRIPT_DIR}/keys/docker-release-signing-key.asc"
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

    wait_for_apt_locks
    apt-get update
    apt-get install -y docker-ce-cli

    info "Docker installed successfully"
}

verify_installation() {
    info "Verifying installation"

    # Check critical tools (Docker might not be available in some environments)
    require_cmds go gofmt clang clang-format staticcheck revive goimports-reviser errcheck govulncheck

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
        info "Docker not available (might be installed but not accessible)"
    fi

    info "All tools verified successfully"
}

main() {
    info "=== Tracee Dependencies Installation (Ubuntu/Debian) ==="

    install_base_packages
    install_golang
    install_clang
    install_go_tools
    install_docker
    verify_installation

    info "=== Tracee dependencies installation completed successfully! ==="
}

main "$@"
