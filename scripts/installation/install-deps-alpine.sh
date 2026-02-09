#!/bin/sh

# Comprehensive dependency installation script for Tracee (Alpine Linux)

set -e

# Source lib.sh for consistent logging and utilities
SCRIPT_DIR="${0%/*}"
__LIB_DIR="${SCRIPT_DIR}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

info "Starting Tracee dependency installation on Alpine Linux"

# Configuration
# When changing GOLANG_VERSION, update the corresponding checksum files in:
#   scripts/installation/checksums/go${GOLANG_VERSION}.linux-amd64.tar.gz.sha256
#   scripts/installation/checksums/go${GOLANG_VERSION}.linux-arm64.tar.gz.sha256
# Get checksums from: https://go.dev/dl/ (click "Show checksum" for each file)
GOLANG_VERSION="1.24.13"
STATICCHECK_VERSION="2025.1"
REVIVE_VERSION="v1.7.0"
GOIMPORTS_REVISER_VERSION="v3.8.2"
ERRCHECK_VERSION="v1.9.0"

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
    info "Installing Go ${GOLANG_VERSION}"
    require_cmds curl tar

    # Detect architecture for Go download
    install_golang_arch=$(uname -m)
    install_golang_goarch=""
    case "${install_golang_arch}" in
        x86_64) install_golang_goarch="amd64" ;;
        aarch64) install_golang_goarch="arm64" ;;
        *)
            die "Unsupported architecture: ${install_golang_arch}"
            ;;
    esac

    install_golang_tarball="go${GOLANG_VERSION}.linux-${install_golang_goarch}.tar.gz"
    install_golang_checksum_file="${SCRIPT_DIR}/checksums/${install_golang_tarball}.sha256"
    install_golang_url="https://go.dev/dl/${install_golang_tarball}"

    # Check that the checksum file exists
    if [ ! -f "${install_golang_checksum_file}" ]; then
        die "Go checksum file not found: ${install_golang_checksum_file}
Please create the checksum file with the SHA256 from https://go.dev/dl/"
    fi

    # Remove any existing Go installation
    rm -f /usr/bin/go /usr/bin/gofmt
    rm -rf /usr/local/go

    # Download Go tarball
    info "Downloading Go ${GOLANG_VERSION}..."
    if ! curl -fsSL -o "/tmp/${install_golang_tarball}" "${install_golang_url}"; then
        die "Failed to download Go tarball from ${install_golang_url}"
    fi

    # Verify the checksum before extraction
    if ! verify_sha256_checksum "/tmp/${install_golang_tarball}" "${install_golang_checksum_file}" "Go ${GOLANG_VERSION}"; then
        rm -f "/tmp/${install_golang_tarball}"
        die "Aborting Go installation due to checksum verification failure"
    fi

    # Checksum verified, proceed with extraction
    info "Extracting Go to /usr/local..."
    tar -C /usr/local -xzf "/tmp/${install_golang_tarball}"
    rm -f "/tmp/${install_golang_tarball}"

    # Create symlinks
    ln -s /usr/local/go/bin/go /usr/bin/go
    ln -s /usr/local/go/bin/gofmt /usr/bin/gofmt

    # Verify installation
    go version
    info "Go ${GOLANG_VERSION} installed successfully"
}

install_clang() {
    info "Installing Clang using centralized script"
    require_cmds bash

    # Call our existing Clang installation script
    bash "${SCRIPT_DIR}/install-clang.sh"

    info "Clang installation completed"
}

install_go_tools() {
    info "Installing Go development tools"
    require_cmds go

    export GOROOT=/usr/local/go
    export GOPATH=/tmp/go
    export PATH=$GOROOT/bin:$GOPATH/bin:$PATH

    # Create GOPATH
    mkdir -p "$GOPATH/bin"

    # Install staticcheck
    info "Installing staticcheck ${STATICCHECK_VERSION}"
    go install "honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}"
    cp "$GOPATH/bin/staticcheck" /usr/bin/

    # Install revive
    info "Installing revive ${REVIVE_VERSION}"
    go install "github.com/mgechev/revive@${REVIVE_VERSION}"
    cp "$GOPATH/bin/revive" /usr/bin/

    # Install goimports-reviser
    info "Installing goimports-reviser ${GOIMPORTS_REVISER_VERSION}"
    go install "github.com/incu6us/goimports-reviser/v3@${GOIMPORTS_REVISER_VERSION}"
    cp "$GOPATH/bin/goimports-reviser" /usr/bin/

    # Install errcheck
    info "Installing errcheck ${ERRCHECK_VERSION}"
    go install "github.com/kisielk/errcheck@${ERRCHECK_VERSION}"
    cp "$GOPATH/bin/errcheck" /usr/bin/

    # Clean up GOPATH
    rm -rf "$GOPATH"

    info "Go tools installed successfully"
}

check_docker() {
    info "Checking Docker availability"

    # In GitHub Actions containers, Docker is available from the host
    # We don't need to install it, just verify it's accessible
    if command -v docker > /dev/null 2>&1; then
        info "Docker is available from host system"
    else
        info "Docker not available - will be provided by GitHub Actions runner"
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
