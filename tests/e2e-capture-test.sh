#!/bin/bash
#
# E2E Capture Test
#
# This script runs end-to-end tests for Tracee's file and network capture features.
# Unlike integration tests that run tracee in-process, this test requires a fully
# built tracee binary since capture tests need to verify that captured files are
# written correctly by the running tracee process.
#
# Usage: ./tests/e2e-capture-test.sh
#
# Prerequisites:
#   - Must be run as root (or with sudo)
#   - Tracee must be built (make tracee)
#   - Docker must be available for network capture tests
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ==============================================================================
# Load Dependencies
# ==============================================================================
__LIB_DIR="${SCRIPT_DIR}/../scripts"
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# ==============================================================================
# Configuration
# ==============================================================================
TRACEE_BIN="${SCRIPT_DIR}/../dist/tracee"

# ==============================================================================
# Pre-flight Checks
# ==============================================================================
if [[ ${UID} -ne 0 ]]; then
    die "need root privileges"
fi

if [[ ! -d "${SCRIPT_DIR}/../signatures" ]]; then
    die "need to be in tracee root directory"
fi

if [[ ! -x "${TRACEE_BIN}" ]]; then
    info "Tracee binary not found at ${TRACEE_BIN}, building..."
    make -C "${SCRIPT_DIR}/.." -j"$(nproc)" tracee
fi

# Verify tracee binary exists after build
if [[ ! -x "${TRACEE_BIN}" ]]; then
    die "could not find tracee executable after build"
fi

# ==============================================================================
# Environment Information
# ==============================================================================
print_section_banner "E2E CAPTURE TEST" "=" 80

KERNEL=$(uname -r)
KERNEL_MAJ=$(echo "${KERNEL}" | cut -d'.' -f1)

info "KERNEL: ${KERNEL}"
info "TRACEE: ${TRACEE_BIN}"
info

if [[ ${KERNEL_MAJ} -lt 5 && "${KERNEL}" != *"el8"* ]]; then
    info "skip test in kernels < 5.0 (and not RHEL), kernel: ${KERNEL}"
    exit 0
fi

# ==============================================================================
# Run E2E Capture Tests
# ==============================================================================
print_section_header "RUNNING CAPTURE TESTS" "=" 80

# Set up Go environment for running tests
GO_ENV_EBPF=""
if [[ -n "${GOROOT:-}" ]]; then
    GO_ENV_EBPF="GOROOT=${GOROOT}"
fi

# The test requires the tracee binary path
export TRACEE_BIN

cd "${SCRIPT_DIR}/.."

# Run the Go tests in the e2e-capture package
# These tests use testutils.NewRunningTracee which runs tracee as a binary
info "Running e2e-capture tests..."

# Build Go tags for eBPF
GO_TAGS_EBPF="ebpf"

# Run the tests
# Note: -p 1 ensures tests run sequentially (important for capture tests)
# Note: -count=1 disables test caching
go test \
    -tags "${GO_TAGS_EBPF}" \
    -timeout 20m \
    -race \
    -v \
    -p 1 \
    -count=1 \
    ./tests/e2e-capture/...

test_status=$?

print_separator '-' 80

if [[ ${test_status} -eq 0 ]]; then
    info "E2E CAPTURE TESTS PASSED"
else
    error "E2E CAPTURE TESTS FAILED"
fi

exit ${test_status}
