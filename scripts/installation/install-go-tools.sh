#!/bin/bash

# Centralized Go tools installation script for Tracee
# Installs staticcheck, revive, goimports-reviser, errcheck, and govulncheck

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
GOVULNCHECK_VERSION="d1f380186385b4f64e00313f31743df8e4b89a77" # v1.1.4
GOPLS_VERSION="5c4433be420451410e8cfd968eda32a818dac087" # gopls/v0.21.1
DELVE_VERSION="498ee9c27223fed032af8856f7a62590a63b9439" # v1.25.2

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

    # Install govulncheck
    info "Installing govulncheck ${GOVULNCHECK_VERSION}"
    go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"
    cp "$GOPATH/bin/govulncheck" /usr/bin/

    # Install gopls (language server for the lsp-go / editor-attach targets)
    info "Installing gopls ${GOPLS_VERSION}"
    go install "golang.org/x/tools/gopls@${GOPLS_VERSION}"
    cp "$GOPATH/bin/gopls" /usr/bin/

    # Install delve (Go debugger for the editor-attach targets)
    info "Installing delve ${DELVE_VERSION}"
    go install "github.com/go-delve/delve/cmd/dlv@${DELVE_VERSION}"
    cp "$GOPATH/bin/dlv" /usr/bin/

    # Clean up GOPATH
    rm -rf "$GOPATH"

    info "Go tools installed successfully"
}

install_go_tools
