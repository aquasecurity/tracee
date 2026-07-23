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

# containerd CLI (ctr) version for the container-runtime enrichment
# integration test. We install ONLY the static `ctr` client from the
# containerd release - no containerd daemon and no systemd unit - so it never
# conflicts with the containerd instance the pre-baked Docker daemon already
# runs. The test drives that existing containerd in a dedicated namespace.
#
# Kept aligned with the github.com/containerd/containerd/v2 module version in
# go.mod so the CLI matches the client library the enricher links against.
#
# When changing CONTAINERD_CLI_VERSION, update the checksum files in:
#   scripts/installation/checksums/containerd-${CONTAINERD_CLI_VERSION}-linux-amd64.tar.gz.sha256
#   scripts/installation/checksums/containerd-${CONTAINERD_CLI_VERSION}-linux-arm64.tar.gz.sha256
# Checksums come from the release asset <tarball>.sha256sum. containerd does not
# publish detached GPG signatures for its release assets (it relies on GitHub
# artifact attestations), so the pinned SHA256 is the integrity anchor here.
CONTAINERD_CLI_VERSION="2.3.3"

install_containerd_cli() {
    info "Installing containerd CLI (ctr ${CONTAINERD_CLI_VERSION})"
    require_cmds curl tar

    local arch goarch
    arch=$(uname -m)
    case "${arch}" in
        x86_64) goarch="amd64" ;;
        aarch64) goarch="arm64" ;;
        *) die "Unsupported architecture: ${arch}" ;;
    esac

    local tarball_name="containerd-${CONTAINERD_CLI_VERSION}-linux-${goarch}.tar.gz"
    local checksum_file="${SCRIPT_DIR}/checksums/${tarball_name}.sha256"
    local download_url="https://github.com/containerd/containerd/releases/download/v${CONTAINERD_CLI_VERSION}/${tarball_name}"

    if [[ ! -f "${checksum_file}" ]]; then
        die "containerd checksum file not found: ${checksum_file}"
    fi

    info "Downloading containerd static release..."
    if ! curl -fsSL -o "/tmp/${tarball_name}" "${download_url}"; then
        die "Failed to download containerd tarball from ${download_url}"
    fi

    if ! verify_sha256_checksum "/tmp/${tarball_name}" "${checksum_file}" "containerd ${CONTAINERD_CLI_VERSION}"; then
        rm -f "/tmp/${tarball_name}"
        die "Aborting ctr installation due to checksum verification failure"
    fi

    # Extract ONLY the ctr client (no daemon, no shims, no service) so Docker's
    # own containerd is left untouched.
    info "Installing ctr to /usr/local/bin..."
    tar -C /usr/local -xzf "/tmp/${tarball_name}" bin/ctr
    rm -f "/tmp/${tarball_name}"

    ctr --version
    info "containerd CLI (ctr) installed successfully"
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

    # Check ctr availability (optional)
    if command -v ctr > /dev/null 2>&1; then
        ctr --version
    else
        info "ctr not available (containerd enrichment test will be skipped)"
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
    install_containerd_cli
    verify_installation

    info "=== Tracee dependencies installation completed successfully! ==="
}

main "$@"
