#!/bin/bash

# Comprehensive dependency installation script for Tracee (CentOS/RHEL/Amazon Linux)
# For use in AMI preparation and CentOS-based environments

set -euo pipefail

# Source lib.sh for consistent logging and utilities
SCRIPT_DIR="${0%/*}"
__LIB_DIR="${SCRIPT_DIR}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

info "Starting Tracee dependency installation on CentOS/RHEL"

# Detect package manager (dnf preferred over yum)
detect_pkg_manager() {
    if command -v dnf > /dev/null 2>&1; then
        echo "dnf"
    elif command -v yum > /dev/null 2>&1; then
        echo "yum"
    else
        die "No supported package manager found (dnf or yum required)"
    fi
}

PKG_MANAGER=$(detect_pkg_manager)
info "Using package manager: ${PKG_MANAGER}"

install_base_packages() {
    info "Installing base packages"

    # Enable EPEL repository for additional packages
    if [[ "${PKG_MANAGER}" == "dnf" ]]; then
        ${PKG_MANAGER} install -y epel-release || ${PKG_MANAGER} install -y \
            "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$(rpm -E %rhel).noarch.rpm" || true
    else
        ${PKG_MANAGER} install -y epel-release || true
    fi

    # Enable CRB (CodeReady Builder) repository for additional packages
    if command -v crb > /dev/null 2>&1; then
        crb enable || true
    elif ${PKG_MANAGER} config-manager --help > /dev/null 2>&1; then
        ${PKG_MANAGER} config-manager --set-enabled crb 2> /dev/null \
            || ${PKG_MANAGER} config-manager --set-enabled powertools 2> /dev/null || true
    fi

    # Use --allowerasing to handle curl-minimal vs curl conflicts in minimal images
    ${PKG_MANAGER} install -y --allowerasing \
        gcc \
        gcc-c++ \
        make \
        pkgconfig \
        zlib-devel \
        elfutils-libelf-devel \
        libzstd-devel \
        curl \
        tar \
        xz \
        git \
        ca-certificates \
        wget \
        iproute \
        iputils \
        nmap-ncat

    # Install protobuf - package name varies by distro version
    ${PKG_MANAGER} install -y protobuf-devel protobuf-compiler 2> /dev/null \
        || ${PKG_MANAGER} install -y protobuf 2> /dev/null \
        || warn "protobuf packages not available - may need manual installation"

    # Install bpftrace if available
    ${PKG_MANAGER} install -y bpftrace 2> /dev/null \
        || warn "bpftrace not available in repositories"

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

    # Remove old Docker installations
    ${PKG_MANAGER} remove -y docker docker-client docker-client-latest \
        docker-common docker-latest docker-latest-logrotate \
        docker-logrotate docker-engine 2> /dev/null || true

    # Install Docker repository
    ${PKG_MANAGER} install -y yum-utils || true
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo 2> /dev/null \
        || ${PKG_MANAGER} config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo || true

    # Install Docker CLI
    ${PKG_MANAGER} install -y docker-ce-cli || {
        warn "Could not install Docker from official repo, trying alternatives"
        ${PKG_MANAGER} install -y docker || true
    }

    info "Docker installed successfully"
}

verify_installation() {
    info "Verifying installation"

    # Check critical tools
    require_cmds go gofmt clang staticcheck revive goimports-reviser errcheck govulncheck

    # Show versions
    info "Installation verification:"
    go version
    clang --version | head -n1

    if command -v clang-format > /dev/null 2>&1; then
        clang-format --version | head -n1
    else
        warn "clang-format not available"
    fi

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
    info "=== Tracee Dependencies Installation (CentOS/RHEL) ==="

    install_base_packages
    install_golang
    install_clang
    install_go_tools
    install_docker
    verify_installation

    info "=== Tracee dependencies installation completed successfully! ==="
}

main "$@"
