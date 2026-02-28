#!/bin/bash

# Centralized Go tools installation script for Tracee
# Installs staticcheck, revive, goimports-reviser, and errcheck

set -euo pipefail

# Source lib.sh for consistent logging and utilities
SCRIPT_DIR="${0%/*}"
__LIB_DIR="${SCRIPT_DIR}/.."
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# Pinned versions (commit hashes) - do not allow external overrides
STATICCHECK_VERSION="5af2e5fc3b08ba46027eb48ebddeba34dc0bd02c" # 2025.1
REVIVE_VERSION="8ece20b0789c517bd3a6742db0daa4dd5928146d" # v1.7.0
GOIMPORTS_REVISER_VERSION="fa5587e51ba33c58734984cb41370a5b2582d5b7" # v3.12.6
ERRCHECK_VERSION="11c27a7ce69d583465d80d808817d22d6653ee34" # v1.9.0

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

install_go_tools
