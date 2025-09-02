#!/bin/bash

# Centralized Clang installation script for Tracee
# Supports Alpine Linux and Ubuntu/Debian environments

set -e

# Source lib.sh for consistent logging and utilities
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "${SCRIPT_DIR}/../lib.sh"

# Configuration - single source of truth for Clang version
CLANG_VERSION=19

# List of all LLVM/Clang tools we manage
CLANG_TOOLS="cc clang clang++ llc lld clangd clang-format llvm-strip llvm-config ld.lld llvm-ar llvm-nm llvm-objcopy llvm-objdump llvm-readelf opt"

# Detect environment
detect_environment() {
    if [ -f /etc/alpine-release ]; then
        echo "alpine"
    elif [ -f /etc/debian_version ]; then
        echo "ubuntu"
    else
        die "Unsupported operating system for Clang installation"
    fi
}

# Alpine installation and symlink setup
install_clang_alpine() {
    info "Installing Clang ${CLANG_VERSION} on Alpine Linux"

    # Verify Alpine-specific commands are available
    require_cmds apk ln rm

    apk add --no-cache \
        clang${CLANG_VERSION} \
        clang${CLANG_VERSION}-extra-tools \
        llvm${CLANG_VERSION} \
        musl-dev \
        libc6-compat

    setup_alpine_symlinks
}

# Set up symlinks for Alpine (no update-alternatives available)
setup_alpine_symlinks() {
    info "Setting up Clang ${CLANG_VERSION} symlinks"

    # Remove existing symlinks (one per line for readability)
    for tool in $CLANG_TOOLS; do
        rm -f /usr/bin/$tool
    done

    # Create new symlinks
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/clang /usr/bin/cc
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/clang /usr/bin/clang
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/clang++ /usr/bin/clang++
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llc /usr/bin/llc
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/lld /usr/bin/lld
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/clangd /usr/bin/clangd
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/clang-format /usr/bin/clang-format
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llvm-strip /usr/bin/llvm-strip
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llvm-config /usr/bin/llvm-config
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/lld /usr/bin/ld.lld
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llvm-ar /usr/bin/llvm-ar
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llvm-nm /usr/bin/llvm-nm
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llvm-objcopy /usr/bin/llvm-objcopy
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llvm-objdump /usr/bin/llvm-objdump
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/llvm-readelf /usr/bin/llvm-readelf
    ln -s /usr/lib/llvm${CLANG_VERSION}/bin/opt /usr/bin/opt
}

# Ubuntu/Debian installation
install_clang_ubuntu() {
    info "Installing Clang ${CLANG_VERSION} on Ubuntu/Debian"

    # Verify Ubuntu-specific commands are available
    require_cmds apt-get update-alternatives ln rm

    # Install base LLVM and Clang packages
    apt-get update
    apt-get install -y \
        llvm-${CLANG_VERSION} \
        clang-${CLANG_VERSION} \
        clang-tools-${CLANG_VERSION}

    # Try to install clang-format-19 directly (separate package)
    if apt-get install -y clang-format-${CLANG_VERSION}; then
        info "clang-format-${CLANG_VERSION} installed successfully"
    else
        warn "clang-format-${CLANG_VERSION} package not available"
    fi

    setup_ubuntu_alternatives
}

# Set up update-alternatives for Ubuntu/Debian
setup_ubuntu_alternatives() {
    info "Setting up update-alternatives for Clang ${CLANG_VERSION}"

    # Remove all existing alternatives to avoid conflicts
    for tool in $CLANG_TOOLS; do
        update-alternatives --remove-all $tool 2>/dev/null || true
    done

    # Check if current clang is already the target version
    if command -v clang >/dev/null 2>&1; then
        current_version=$(clang --version | grep -o "clang version [0-9]\+" | head -1 | grep -o "[0-9]\+")
        if [ "$current_version" = "$CLANG_VERSION" ]; then
            info "Default clang is already version ${CLANG_VERSION}"
            return
        fi
    fi

    # Set up clang alternative
    if [ -f /usr/bin/clang-${CLANG_VERSION} ]; then
        update-alternatives --install /usr/bin/clang clang /usr/bin/clang-${CLANG_VERSION} $((CLANG_VERSION * 10)) \
            --slave /usr/bin/cc cc /usr/bin/clang-${CLANG_VERSION}
    fi

    # Set up clang++ alternative if available
    if [ -f /usr/bin/clang++-${CLANG_VERSION} ]; then
        update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-${CLANG_VERSION} $((CLANG_VERSION * 10))
    fi

    # Set up clang-format alternative if available
    if [ -f /usr/bin/clang-format-${CLANG_VERSION} ]; then
        update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-${CLANG_VERSION} $((CLANG_VERSION * 10))
    fi
}

# Verify installation
verify_installation() {
    info "Verifying Clang installation"

    # Use require_cmds to verify essential tools are available
    require_cmds clang

    # Check clang version
    if command -v clang >/dev/null 2>&1; then
        clang_version_output=$(clang --version 2>/dev/null | head -1 || echo "")
        info "Clang: $clang_version_output"
    else
        warn "clang command not found"
    fi

    # Check clang-format version if available
    if command -v clang-format >/dev/null 2>&1; then
        clang_format_version_output=$(clang-format --version 2>/dev/null | head -1 || echo "")
        info "clang-format: $clang_format_version_output"
    else
        warn "clang-format command not found"
    fi
}

# Main installation logic
main() {
    info "Starting Clang ${CLANG_VERSION} installation for Tracee"

    OS_TYPE=$(detect_environment)
    info "Detected environment: $OS_TYPE"

    case "$OS_TYPE" in
        "alpine")
            install_clang_alpine
            ;;
        "ubuntu")
            install_clang_ubuntu
            ;;
        *)
            die "Unsupported operating system: $OS_TYPE"
            ;;
    esac

    verify_installation
    info "Clang ${CLANG_VERSION} installation completed successfully!"
}

# Run main function
main