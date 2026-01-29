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
    
    # Configure Go environment for user if USER_NAME and USER_HOME are set
    if [ -n "${USER_NAME}" ] && [ -n "${USER_HOME}" ] && [ -d "${USER_HOME}" ]; then
        info "Configuring Go environment for ${USER_NAME} in ${USER_HOME}/.bashrc"
        
        # Add Go paths to .bashrc if not already present
        if ! grep -q "GOROOT" "${USER_HOME}/.bashrc" 2>/dev/null; then
            cat >> "${USER_HOME}/.bashrc" << 'EOF'

# Go environment configuration
export GOROOT="/usr/local/go"
export GOPATH="${HOME}/go"
export GOCACHE="${HOME}/.cache/go-build"
export PATH="${GOROOT}/bin:${GOPATH}/bin:${PATH}"
EOF
            info "Go environment added to ${USER_HOME}/.bashrc"
        else
            info "Go environment already configured in .bashrc"
        fi
        
        # Create Go directories with proper ownership
        mkdir -p "${USER_HOME}/go" "${USER_HOME}/.cache/go-build"
        chown -R "${USER_NAME}:${USER_NAME}" "${USER_HOME}/go" "${USER_HOME}/.cache"
        info "Go directories created in ${USER_HOME}"
    fi
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

install_docker() {
    info "Installing Docker"
    require_cmds apt-get curl

    # Install lsb-release for Ubuntu codename detection
    apt-get update
    apt-get install -y lsb-release

    # Add Docker GPG key and repository
    rm -f /usr/share/keyrings/docker-archive-keyring.gpg
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

    wait_for_apt_locks
    apt-get update
    # Install full Docker engine, not just CLI
    apt-get install -y docker-ce docker-ce-cli containerd.io

    # Enable and start Docker service
    systemctl enable docker
    systemctl start docker

    info "Docker installed successfully"
    
    # Add user to docker group if USER_NAME is set and not root
    if [ -n "${USER_NAME}" ] && [ "${USER_NAME}" != "root" ]; then
        if getent group docker >/dev/null 2>&1; then
            usermod -aG docker "${USER_NAME}"
            info "Added ${USER_NAME} to docker group"
        else
            info "Docker group not found, skipping group assignment"
        fi
    fi
}

setup_user_vars() {
    # Setup USER_NAME and USER_HOME variables for user-specific configuration
    # Use USER_NAME env var if set, otherwise default to current user ($USER)
    # Caller can override with: USER_NAME=myuser ./install-deps-ubuntu.sh
    
    USER_NAME="${USER_NAME:-${USER}}"
    
    # Verify user exists
    if ! id "${USER_NAME}" >/dev/null 2>&1; then
        info "User ${USER_NAME} not found, skipping user-specific configuration"
        USER_NAME=""
        USER_HOME=""
        return 0
    fi
    
    # Get home directory from passwd database
    USER_HOME=$(getent passwd "${USER_NAME}" | cut -d: -f6)
    
    if [ -z "${USER_HOME}" ]; then
        info "Could not determine home directory for user ${USER_NAME}, skipping user-specific configuration"
        USER_NAME=""
        USER_HOME=""
        return 0
    fi
    
    info "User configuration will be applied to: ${USER_NAME} (home: ${USER_HOME})"
    
    # Export for child processes
    export USER_NAME
    export USER_HOME
}

verify_installation() {
    info "Verifying installation"

    # Check critical tools (Docker might not be available in some environments)
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
        info "Docker not available (might be installed but not accessible)"
    fi

    info "All tools verified successfully"
}

main() {
    info "=== Tracee Dependencies Installation (Ubuntu/Debian) ==="
    
    # Setup user variables for user-specific configuration
    setup_user_vars
    
    install_base_packages
    install_golang
    install_clang
    install_go_tools
    install_docker
    verify_installation

    info "=== Tracee dependencies installation completed successfully! ==="
}

main "$@"
