#!/bin/bash

#
# Local validation: build and test tracee with upstream libbpfgo.
#
# Swaps the pinned libbpfgo dependency for upstream main, builds
# tracee, runs unit tests, then restores go.mod/go.sum. Triggered
# via 'make test-upstream-libbpfgo'.
#
# CI runs the full PR test suite (unit, integration, performance,
# E2E/kernel) against upstream libbpfgo via workflow_call -- see
# .github/workflows/test-upstream-libbpfgo.yaml.
#

info() {
    echo -n "INFO: "
    echo "$@"
}

error_exit() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

git_setup() {
    git add go.mod go.sum
    if ! go get github.com/aquasecurity/libbpfgo@main; then
        git restore --staged go.mod go.sum
        error_exit "could not go get libbpfgo@main"
    fi
}

git_restore() {
    git checkout go.mod go.sum
    git restore --staged go.mod go.sum
}

BASE_DIR="$(dirname "$(realpath "${0}")")"
TRACEE_DIR="$(realpath "${BASE_DIR}"/..)"
GO_ENV_EBPF=("$@")
export "${GO_ENV_EBPF[@]}"

git_setup
trap git_restore ERR

set -e

info "Building tracee with upstream libbpfgo..."
STATIC=1 make -C "${TRACEE_DIR}"

info "Running unit tests with upstream libbpfgo..."
make -C "${TRACEE_DIR}" test-unit

set +e

git_restore

info "SUCCESS"

exit 0
