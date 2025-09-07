#!/bin/sh

# Comprehensive dependency installation script for Tracee (Alpine Linux)

set -e

# Source lib.sh for consistent logging and utilities  
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/../lib.sh"

info "Starting Tracee dependency installation on Alpine Linux"

# Configuration
GOLANG_VERSION="1.24.0"
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
        binutils-gold

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
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) GOARCH="amd64" ;;
        aarch64) GOARCH="arm64" ;;
        *)
            error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    # Remove any existing Go installation
    rm -f /usr/bin/go /usr/bin/gofmt
    rm -rf /usr/local/go
    
    # Download and install Go
    curl -L -o /tmp/golang.tar.gz "https://go.dev/dl/go${GOLANG_VERSION}.linux-${GOARCH}.tar.gz"
    tar -C /usr/local -xzf /tmp/golang.tar.gz
    rm /tmp/golang.tar.gz
    
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
    bash "$SCRIPT_DIR/install-clang.sh"
    
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
    if command -v docker >/dev/null 2>&1; then
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
    if command -v docker >/dev/null 2>&1; then
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
