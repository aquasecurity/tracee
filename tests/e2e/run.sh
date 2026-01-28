#!/bin/bash
#
# E2E Instrumentation Test Coordinator
#
# This script orchestrates the execution of core and extended instrumentation tests.
# Test implementations are in:
#   - lib-core.sh (core tests implementation)
#   - lib-extended.sh (extended tests implementation, gitignored)
#   - TODO: update run-net.sh to be orchestrated by this script
#   - TODO: update run-kernel.sh to be orchestrated by this script
#

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# ==============================================================================
# Load Dependencies
# ==============================================================================
# shellcheck disable=SC1091
. "${SCRIPT_DIR}/common.sh"

# ==============================================================================
# Help Functions
# ==============================================================================
# Show help message for --help flag
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --keep-artifacts    Don't delete test artifacts (logs and output files)"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Test Selection (via INSTTESTS environment variable):"
    echo "  INSTTESTS=all       Run all available tests (default)"
    echo "  INSTTESTS=core      Run only core tests"
    echo "  INSTTESTS=extended  Run only extended tests"
    echo "  INSTTESTS='TEST1 TEST2'  Run specific tests"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run all tests"
    echo "  INSTTESTS=core $0                     # Run only core tests"
    echo "  INSTTESTS='VFS_WRITE DNS_DATA_STORE' $0  # Run specific tests"
}

# Show usage hint for error scenarios
show_usage_hint() {
    error ""
    error "Available tests:"
    error "  Core: ${INSTTESTS_CORE_AVAILABLE}"
    if [[ -n "${INSTTESTS_EXTENDED_AVAILABLE}" ]]; then
        error "  Extended: ${INSTTESTS_EXTENDED_AVAILABLE}"
    fi
    error ""
    error "Usage: INSTTESTS=<value> $0"
    error "  where <value> can be:"
    error "    - 'all' (run all available tests)"
    error "    - 'core' (run only core tests)"
    error "    - 'extended' (run only extended tests)"
    error "    - specific test names (e.g., 'VFS_WRITE DNS_DATA_STORE')"
}

# ==============================================================================
# Command Line Arguments
# ==============================================================================
KEEP_ARTIFACTS=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-artifacts)
            KEEP_ARTIFACTS=1
            shift
            ;;
        -h | --help)
            show_help
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            error "Use --help for usage information"
            exit 1
            ;;
    esac
done

# ==============================================================================
# Configuration
# ==============================================================================
# Export variables used by sourced test implementation files
ARCH=$(uname -m)
export ARCH
export KERNEL # Set later, used by core_test_setup
TRACEE_STARTUP_TIMEOUT=30
TRACEE_SHUTDOWN_TIMEOUT=30
SCRIPT_TMP_DIR=/tmp
TRACEE_TMP_DIR=/tmp/tracee

# ==============================================================================
# Test List Configuration
# ==============================================================================
# Capture user/CI selection BEFORE sourcing implementation files
USER_INSTTESTS=${INSTTESTS:-}

# ==============================================================================
# Test Configuration Map
# ==============================================================================
# Must be declared BEFORE sourcing implementation files
# Implementation files populate this via add_test_config calls
# shellcheck disable=SC2034  # Used via nameref in common.sh and implementation files
declare -A TEST_CONFIG_MAP

# ==============================================================================
# Source Test Implementations
# ==============================================================================
# Implementation files define INSTTESTS_*_AVAILABLE and test phase functions

# Source core test implementation (required)
CORE_TEST_IMPL="${SCRIPT_DIR}/lib-core.sh"
if [[ ! -f "${CORE_TEST_IMPL}" ]]; then
    die "Core test implementation not found: ${CORE_TEST_IMPL}"
fi
# shellcheck disable=SC1090
. "${CORE_TEST_IMPL}"

# Validate core tests available list was defined
if [[ -z "${INSTTESTS_CORE_AVAILABLE:-}" ]]; then
    die "INSTTESTS_CORE_AVAILABLE not defined in ${CORE_TEST_IMPL}"
fi

# Source extended test implementation (optional - private repo only)
EXTENDED_TEST_IMPL="${SCRIPT_DIR}/lib-extended.sh"
if [[ -f "${EXTENDED_TEST_IMPL}" ]]; then
    info "Loading extended test implementation from ${EXTENDED_TEST_IMPL}"
    # shellcheck disable=SC1090
    . "${EXTENDED_TEST_IMPL}"

    # Validate extended tests available list was defined
    if [[ -z "${INSTTESTS_EXTENDED_AVAILABLE:-}" ]]; then
        die "INSTTESTS_EXTENDED_AVAILABLE not defined in ${EXTENDED_TEST_IMPL}"
    fi
else
    # No extended tests available - define no-op functions
    INSTTESTS_EXTENDED_AVAILABLE=""

    # Define stub functions so coordinator can safely call them
    extended_init_test_config() { return 0; }
    extended_should_skip_test() { return 0; }
    extended_test_setup() { return 0; }
    extended_test_run() { return 0; }
    extended_test_check() { return 0; }
fi

# ==============================================================================
# Test Selection and Routing
# ==============================================================================
# Route user selection to core or extended based on availability
#
# Behavior:
#   - INSTTESTS not set: Run all available tests (core + extended)
#   - INSTTESTS="all": Same as not set, run everything
#   - INSTTESTS="core": Run all core tests only
#   - INSTTESTS="extended": Run all extended tests only
#   - INSTTESTS="TEST1 TEST2": Auto-route specified tests (strict validation)

if [[ -n "${USER_INSTTESTS}" ]]; then
    # Handle special keywords first
    case "${USER_INSTTESTS}" in
        all)
            info "Running all available tests"
            INSTTESTS_CORE=${INSTTESTS_CORE_AVAILABLE}
            INSTTESTS_EXTENDED=${INSTTESTS_EXTENDED_AVAILABLE}
            ;;
        core)
            info "Running all core tests"
            INSTTESTS_CORE=${INSTTESTS_CORE_AVAILABLE}
            INSTTESTS_EXTENDED=""
            ;;
        extended)
            info "Running all extended tests"
            INSTTESTS_CORE=""
            INSTTESTS_EXTENDED=${INSTTESTS_EXTENDED_AVAILABLE}
            ;;
        *)
            # User specified individual tests - route them automatically with strict validation
            INSTTESTS_CORE=""
            INSTTESTS_EXTENDED=""
            invalid_tests=""

            for test in ${USER_INSTTESTS}; do
                # Check if test is in core available list
                if grep -qw "${test}" <<< "${INSTTESTS_CORE_AVAILABLE}"; then
                    INSTTESTS_CORE="${INSTTESTS_CORE} ${test}"
                # Check if test is in extended available list
                elif [[ -n "${INSTTESTS_EXTENDED_AVAILABLE}" ]] && grep -qw "${test}" <<< "${INSTTESTS_EXTENDED_AVAILABLE}"; then
                    INSTTESTS_EXTENDED="${INSTTESTS_EXTENDED} ${test}"
                else
                    # Collect invalid tests
                    invalid_tests="${invalid_tests} ${test}"
                fi
            done

            # Strict validation: fail if any test is invalid
            if [[ -n "${invalid_tests}" ]]; then
                error "Invalid test(s) specified:${invalid_tests}"
                show_usage_hint
                die "Cannot proceed with invalid tests"
            fi

            # Trim leading spaces
            INSTTESTS_CORE=${INSTTESTS_CORE# }
            INSTTESTS_EXTENDED=${INSTTESTS_EXTENDED# }
            ;;
    esac
else
    # Default: run all available tests
    INSTTESTS_CORE=${INSTTESTS_CORE_AVAILABLE}
    INSTTESTS_EXTENDED=${INSTTESTS_EXTENDED_AVAILABLE}
fi

# ==============================================================================
# Validation
# ==============================================================================
# Check if we have any tests to run

if [[ -z "${INSTTESTS_CORE}" && -z "${INSTTESTS_EXTENDED}" ]]; then
    error "No tests to run!"
    show_usage_hint
    die "Please specify valid tests"
fi

info "Tests to run:"
if [[ -n "${INSTTESTS_CORE}" ]]; then
    info "  Core: ${INSTTESTS_CORE}"
fi
if [[ -n "${INSTTESTS_EXTENDED}" ]]; then
    info "  Extended: ${INSTTESTS_EXTENDED}"
fi

# ==============================================================================
# Initialize Test Configurations
# ==============================================================================
# Now that we know which tests to run, initialize their configurations

if [[ -n "${INSTTESTS_CORE}" ]]; then
    core_init_test_config
fi

if [[ -n "${INSTTESTS_EXTENDED}" ]] && declare -f extended_init_test_config > /dev/null; then
    extended_init_test_config
fi

TRACEE_POLICY_PATH="./tests/policies/e2e/"
export TESTS_DIR="${SCRIPT_DIR}/core/scripts" # Used by core_test_run
TRACEE_E2E_BIN="./dist/tracee-e2e"

# ==============================================================================
# Pre-flight Checks
# ==============================================================================
if [[ ${UID} -ne 0 ]]; then
    die "need root privileges"
fi

if [[ ! -d ./signatures ]]; then
    die "need to be in tracee root directory"
fi

rm -rf ${TRACEE_TMP_DIR:?}/* || die "could not delete ${TRACEE_TMP_DIR}"

KERNEL=$(uname -r)
KERNEL_MAJ=$(echo "${KERNEL}" | cut -d'.' -f1)

if [[ ${KERNEL_MAJ} -lt 5 && "${KERNEL}" != *"el8"* ]]; then
    info "skip test in kernels < 5.0 (and not RHEL), kernel: ${KERNEL}"
    exit 0
fi

# ==============================================================================
# Environment Information
# ==============================================================================
print_test_header "ENVIRONMENT"
info "KERNEL: ${KERNEL}"
info "CLANG: $(clang --version)"
info "GO: $(go version)"
print_test_separator

# ==============================================================================
# Build Tracee
# ==============================================================================
print_test_header "COMPILING TRACEE-E2E AND LSM-CHECK"
set -e
make -j"$(nproc)" tracee-e2e lsm-check
set +e
print_test_separator

if [[ ! -x ./dist/tracee-e2e ]]; then
    die "could not find tracee-e2e executable"
fi

# ==============================================================================
# Initialize Test State
# ==============================================================================
logfile="${SCRIPT_TMP_DIR}/tracee-log-$$"
outputfile="${SCRIPT_TMP_DIR}/tracee-output-$$"
rm -f "${outputfile}" "${logfile}"

# ==============================================================================
# PHASE 1: SETUP TESTS
# ==============================================================================
print_test_header "SETUP TESTS"

# Setup core tests
for TEST in ${INSTTESTS_CORE}; do
    print_test_header "${TEST}" "SETUP"
    core_test_setup "${TEST}"
    print_test_separator
done

# Setup extended tests
for TEST in ${INSTTESTS_EXTENDED}; do
    print_test_header "${TEST}" "SETUP"
    extended_test_setup "${TEST}"
    print_test_separator
done

# ==============================================================================
# PHASE 2: START TRACEE
# ==============================================================================
print_test_header "START TRACE"
./scripts/tracee_start.sh \
    --bin "${TRACEE_E2E_BIN}" \
    -w "${TRACEE_TMP_DIR}" \
    -o "${outputfile}" \
    -l "${logfile}" \
    -L debug \
    -t "${TRACEE_STARTUP_TIMEOUT}" \
    -- \
    --output sort-events \
    --enrichment decoded-data \
    --stores process \
    --stores dns \
    --server grpc-address=unix:/tmp/tracee.sock \
    --policy "${TRACEE_POLICY_PATH}"

last_status=$?
if [[ ${last_status} -ne 0 ]]; then
    die "tracee startup failed"
fi
print_test_separator

# ==============================================================================
# PHASE 3: RUN TESTS
# ==============================================================================
print_test_header "RUNNING TESTS"
declare -A test_pids_map
max_internal_sleep=0
max_test_timeout=0

# Run core tests
for TEST in ${INSTTESTS_CORE}; do
    print_test_header "${TEST}" "RUNNING"

    # Check for skip conditions
    if core_should_skip_test "${TEST}"; then
        info "skipping ${TEST}"
        print_test_separator
        continue
    fi

    test_timeout=$(get_test_timeout TEST_CONFIG_MAP "${TEST}")
    test_sleep=$(get_test_sleep TEST_CONFIG_MAP "${TEST}")

    # Track maximum sleep and timeout
    if [[ "${test_sleep}" -gt "${max_internal_sleep}" ]]; then
        max_internal_sleep="${test_sleep}"
    fi
    if [[ "${test_timeout}" -gt "${max_test_timeout}" ]]; then
        max_test_timeout="${test_timeout}"
    fi

    core_test_run "${TEST}" test_pids_map "${test_timeout}" "${test_sleep}"
    print_test_separator
done

# Run extended tests
for TEST in ${INSTTESTS_EXTENDED}; do
    print_test_header "${TEST}" "RUNNING"

    # Check for skip conditions
    if extended_should_skip_test "${TEST}"; then
        info "skipping ${TEST}"
        print_test_separator
        continue
    fi

    test_timeout=$(get_test_timeout TEST_CONFIG_MAP "${TEST}")
    test_sleep=$(get_test_sleep TEST_CONFIG_MAP "${TEST}")

    # Track maximum sleep and timeout
    if [[ "${test_sleep}" -gt "${max_internal_sleep}" ]]; then
        max_internal_sleep="${test_sleep}"
    fi
    if [[ "${test_timeout}" -gt "${max_test_timeout}" ]]; then
        max_test_timeout="${test_timeout}"
    fi

    extended_test_run "${TEST}" test_pids_map "${test_timeout}" "${test_sleep}"
    print_test_separator
done

# ==============================================================================
# PHASE 4: WAIT FOR TEST COMPLETION
# ==============================================================================
print_test_header "WAITING FOR TESTS TO COMPLETE"
info "Waiting for all tests to complete (max timeout: ${max_test_timeout}s, max internal sleep: ${max_internal_sleep}s)..."

for test_name in "${!test_pids_map[@]}"; do
    pid="${test_pids_map[$test_name]}"
    test_output_file="/tmp/test_${test_name,,}_$$"

    if wait "$pid"; then
        info "Test ${test_name} completed successfully"
    else
        exit_status=$?
        info "Test ${test_name} failed with exit status ${exit_status}"
    fi

    if [[ ! -f "${test_output_file}" ]]; then
        error "  Test output file for ${test_name} not found"
        continue
    fi

    # Show output if file has content
    if [[ -s "${test_output_file}" ]]; then
        info "  Output from ${test_name} test:"
        while IFS= read -r line; do
            info "    ${line}"
        done < "${test_output_file}"
    fi
    rm -f "${test_output_file}"

    # Extract PROCTREE_DATA_STORE signature logs from Tracee log file
    if [[ "${test_name}" == "PROCTREE_DATA_STORE" && -f "${logfile}" ]]; then
        signature_logs=$(grep '\[e2eProcessTreeDataStore\]' "${logfile}" 2> /dev/null || true)
        if [[ -n "${signature_logs}" ]]; then
            info "  PROCTREE_DATA_STORE signature logs from Tracee:"
            while IFS= read -r line; do
                info "    ${line}"
            done <<< "${signature_logs}"
        fi
    fi
done
print_test_separator

# Wait for event processing
print_test_header "WAIT FOR EVENTS TO BE PROCESSED"
info "Waiting for more 5 seconds for event processing"
sleep 5
print_test_separator

# ==============================================================================
# PHASE 5: STOP TRACEE
# ==============================================================================
print_test_header "STOP TRACE"
./scripts/tracee_stop.sh \
    -w "${TRACEE_TMP_DIR}" \
    -t "${TRACEE_SHUTDOWN_TIMEOUT}"

last_status=$?
if [[ ${last_status} -ne 0 ]]; then
    die "tracee shutdown failed, trying to check for results may be misleading"
fi
print_test_separator

# ==============================================================================
# PHASE 6: CHECK TEST RESULTS
# ==============================================================================
print_test_header "CHECKING TESTS RESULTS"
anyerror=""

# Check core test results
for TEST in ${INSTTESTS_CORE}; do
    found=0
    print_test_header "${TEST}" "CHECKING"

    # Check for skip conditions
    if core_should_skip_test "${TEST}"; then
        info "skipped ${TEST} test"
        print_test_separator
        continue
    fi

    if core_test_check "${TEST}" "${outputfile}" "${logfile}"; then
        found=1
    else
        found=0
    fi

    info
    if [[ ${found} -eq 1 ]]; then
        info "${TEST}: SUCCESS"
    else
        anyerror="${anyerror}${TEST},"
        info "${TEST}: FAILED, critical logs from tracee:"
        filter_critical_logs "${logfile}"
        info "${TEST}: FAILED, events from tracee:"
        cat "${outputfile}"
    fi
    print_test_separator
done

# Check extended test results
for TEST in ${INSTTESTS_EXTENDED}; do
    found=0
    print_test_header "${TEST}" "CHECKING"

    # Check for skip conditions
    if extended_should_skip_test "${TEST}"; then
        info "skipped ${TEST} test"
        print_test_separator
        continue
    fi

    if extended_test_check "${TEST}" "${outputfile}" "${logfile}"; then
        found=1
    else
        found=0
    fi

    info
    if [[ ${found} -eq 1 ]]; then
        info "${TEST}: SUCCESS"
    else
        anyerror="${anyerror}${TEST},"
        info "${TEST}: FAILED, critical logs from tracee:"
        filter_critical_logs "${logfile}"
        info "${TEST}: FAILED, events from tracee:"
        cat "${outputfile}"
    fi
    print_test_separator
done

info

# ==============================================================================
# Cleanup and Summary
# ==============================================================================
cleanup_test_artifact_files "${KEEP_ARTIFACTS}" "${outputfile}" "${logfile}"
rm -rf "${TRACEE_TMP_DIR}"

info
if [[ "${anyerror}" != "" ]]; then
    die "FAILED TESTS: ${anyerror::-1}"
fi

info "ALL TESTS PASSED"
exit 0
