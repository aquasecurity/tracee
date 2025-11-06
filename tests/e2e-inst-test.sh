#!/bin/bash

#
# This test is executed by github workflows inside the action runners
#

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "${SCRIPT_DIR}/e2e-common.sh"

ARCH=$(uname -m)

TRACEE_STARTUP_TIMEOUT=30
TRACEE_SHUTDOWN_TIMEOUT=30
SCRIPT_TMP_DIR=/tmp
TRACEE_TMP_DIR=/tmp/tracee

# Default test to run if no other is given
TESTS=${INSTTESTS:=VFS_WRITE CONTAINERS_DATA_SOURCE WRITABLE_DATA_SOURCE DNS_DATA_SOURCE PROCTREE_DATA_SOURCE PROCESS_EXECUTE_FAILED LSM_TEST}

TRACEE_POLICY_PATH="./tests/policies/inst/"

# shellcheck disable=SC2034  # Used via nameref in e2e-common.sh functions
declare -A TEST_CONFIG_MAP

#                               <test_name>                 <policy_name>                 <timeout_sec> <sleep_sec>
add_test_config TEST_CONFIG_MAP "SET_FS_PWD"                "set-fs-pwd-test"             5              0
add_test_config TEST_CONFIG_MAP "WRITABLE_DATA_SOURCE"      "writable-ds-test"            40             0
add_test_config TEST_CONFIG_MAP "SECURITY_PATH_NOTIFY"      "security-path-notify-test"   5              0
add_test_config TEST_CONFIG_MAP "SUSPICIOUS_SYSCALL_SOURCE" "suspicious-syscall-src-test" 10             0
add_test_config TEST_CONFIG_MAP "CONTAINERS_DATA_SOURCE"    "containers-ds-test"          10             5
add_test_config TEST_CONFIG_MAP "PROCTREE_DATA_SOURCE"      "proctree-ds-test"            15             10
add_test_config TEST_CONFIG_MAP "HOOKED_SYSCALL"            "hooked-syscall-test"         10             5
add_test_config TEST_CONFIG_MAP "PROCESS_EXECUTE_FAILED"    "execute-failed-test"         5              2
add_test_config TEST_CONFIG_MAP "STACK_PIVOT"               "stack-pivot-test"            10             5
add_test_config TEST_CONFIG_MAP "FTRACE_HOOK"               "ftrace-hook-test"            15             5
add_test_config TEST_CONFIG_MAP "BPF_ATTACH"                "bpf-attach-test"             15             5
add_test_config TEST_CONFIG_MAP "DNS_DATA_SOURCE"           "dns-ds-test"                 10             0
add_test_config TEST_CONFIG_MAP "SECURITY_INODE_RENAME"     "security-inode-rename-test"  10             2
add_test_config TEST_CONFIG_MAP "FILE_MODIFICATION"         "file-modification-test"      5              0
add_test_config TEST_CONFIG_MAP "LSM_TEST"                  "lsm-test"                    5              0
add_test_config TEST_CONFIG_MAP "VFS_WRITE"                 "vfs-write-test"              5              0

# Command line options
KEEP_ARTIFACTS=0

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-artifacts)
            KEEP_ARTIFACTS=1
            shift
            ;;
        -h | --help)
            echo "Usage: $0 [--keep-artifacts] [--help]"
            echo "  --keep-artifacts    Don't delete test artifacts (logs and output files) after completion"
            echo "  --help              Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done



# Function to check if a test should be skipped
should_skip_test() {
    local test_name="$1"

    case "${test_name}" in
        HOOKED_SYSCALL)
            [[ "${skip_hooked_syscall}" -eq 1 ]]
            ;;
        FTRACE_HOOK)
            [[ "${skip_ftrace_hook}" -eq 1 ]]
            ;;
        SECURITY_PATH_NOTIFY)
            [[ "${skip_security_path_notify}" -eq 1 ]]
            ;;
        SUSPICIOUS_SYSCALL_SOURCE)
            [[ "${skip_suspicious_syscall_source}" -eq 1 ]]
            ;;
        STACK_PIVOT)
            [[ "${skip_stack_pivot}" -eq 1 ]]
            ;;
        LSM_TEST)
            [[ "${lsm_test_not_supported}" -eq 1 ]]
            ;;
        *)
            false
            ;;
    esac
}

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

TESTS_DIR="${SCRIPT_DIR}/e2e-inst-signatures/scripts"
SIG_DIR="${SCRIPT_DIR}/../dist/e2e-inst-signatures"

print_test_header "ENVIRONMENT"
info "KERNEL: ${KERNEL}"
info "CLANG: $(clang --version)"
info "GO: $(go version)"
print_test_separator

print_test_header "COMPILING TRACEE, SIGNATURES AND LSM-CHECK"
set -e
make -j"$(nproc)" tracee e2e-inst-signatures lsm-check
set +e
print_test_separator

# check if tracee was built correctly
if [[ ! -x ./dist/tracee ]]; then
    die "could not find tracee executable"
fi

logfile="${SCRIPT_TMP_DIR}/tracee-log-$$"
outputfile="${SCRIPT_TMP_DIR}/tracee-output-$$"

# remove old log and output files
rm -f "${outputfile}"
rm -f "${logfile}"

skip_hooked_syscall=0
skip_ftrace_hook=0
skip_security_path_notify=0
skip_suspicious_syscall_source=0
skip_stack_pivot=0
lsm_test_not_supported=0

# Setup tests and skips
# Some tests might need special setup (like running before tracee)
print_test_header "SETUP TESTS"
for TEST in ${TESTS}; do
    print_test_header "${TEST}" "SETUP"

    case ${TEST} in
        HOOKED_SYSCALL)
            # TODO: install kernel headers in the AMI images
            if [[ ! -d /lib/modules/${KERNEL}/build ]]; then
                info "skip hooked_syscall test, no kernel headers"
                skip_hooked_syscall=1
            fi
            if [[ "${KERNEL}" == *"amzn"* ]]; then
                info "skip hooked_syscall test in amazon linux"
                skip_hooked_syscall=1
            fi
            if [[ ${ARCH} == "aarch64" ]]; then
                info "skip hooked_syscall test in aarch64"
                skip_hooked_syscall=1
            fi
            if [[ "${skip_hooked_syscall}" -eq 0 ]]; then
                ./tests/e2e-inst-signatures/scripts/hooked_syscall.sh --build --install
            fi
            ;;

        FTRACE_HOOK)
            # TODO: install kernel headers in the AMI images
            if [[ ! -d /lib/modules/${KERNEL}/build ]]; then
                info "skip ftrace_hook test, no kernel headers"
                skip_ftrace_hook=1
            fi
            if [[ "${KERNEL}" == *"amzn"* ]]; then
                info "skip ftrace_hook test in amazon linux"
                skip_ftrace_hook=1
            fi
            if [[ ${ARCH} == "aarch64" ]]; then
                info "skip ftrace_hook test in aarch64"
                skip_ftrace_hook=1
            fi
            if [[ "${skip_ftrace_hook}" -eq 0 ]]; then
                ./tests/e2e-inst-signatures/scripts/ftrace_hook.sh --build
            fi
            ;;

        SECURITY_PATH_NOTIFY)
            if ! grep -qw "security_path_notify" /proc/kallsyms; then
                info "skip security_path_notify test on kernel ${KERNEL} (security hook doesn't exist)"
                skip_security_path_notify=1
            else
                info "compiling security path notify test..."
                if ! ./tests/e2e-inst-signatures/scripts/security_path_notify.sh --build; then
                    error "could not compile security_path_notify"
                fi
            fi
            ;;

        SUSPICIOUS_SYSCALL_SOURCE)
            if grep -qP "trace.*vma_store" /proc/kallsyms; then
                info "skip ${TEST} test on kernel ${KERNEL} (VMAs stored in maple tree)"
                skip_suspicious_syscall_source=1
            else
                info "compiling suspicious syscall source test..."
                if ! ./tests/e2e-inst-signatures/scripts/suspicious_syscall_source.sh --build; then
                    error "could not compile suspicious_syscall_source"
                fi
            fi
            ;;

        STACK_PIVOT)
            if grep -qP "trace.*vma_store" /proc/kallsyms; then
                info "skip ${TEST} test on kernel ${KERNEL} (VMAs stored in maple tree)"
                skip_stack_pivot=1
            else
                info "compiling stack pivot test..."
                if ! ./tests/e2e-inst-signatures/scripts/stack_pivot.sh --build; then
                    error "could not compile stack_pivot"
                fi
            fi
            ;;

        WRITABLE_DATA_SOURCE)
            info "building writable data source test..."
            if ! ./tests/e2e-inst-signatures/scripts/writable_data_source.sh --build; then
                error "could not build writable_data_source"
            fi
            ;;

        CONTAINERS_DATA_SOURCE)
            info "pulling container image for containers data source test..."
            if ! ./tests/e2e-inst-signatures/scripts/containers_data_source.sh --install; then
                error "could not pull container image"
                # Note: don't skip this test so it can fail
            fi
            ;;

        BPF_ATTACH)
            if ! ./tests/e2e-inst-signatures/scripts/bpf_attach.sh --install; then
                error "could not install bpftrace"
                # Note: don't skip this test so it can fail
            fi
            ;;

        LSM_TEST)
            # Test LSM BPF support using Tracee's actual BPF loading test
            info "testing LSM BPF support using actual BPF loading..."
            if [[ ! -x ./dist/lsm-check ]]; then
                error "skip lsm_test on kernel ${KERNEL} (lsm-check binary not found)"
                lsm_test_not_supported=1
            elif ./dist/lsm-check -q; then
                info "LSM BPF support confirmed - test will run normally"
            else
                info "skip lsm_test on kernel ${KERNEL} (LSM BPF not supported)"
                lsm_test_not_supported=1
            fi
            ;;
        PROCTREE_DATA_SOURCE)
            info "compiling proctree data source test..."
            if ! ./tests/e2e-inst-signatures/scripts/proctree_data_source.sh --build; then
                error "could not compile proctree_data_source"
            fi
            # Set up the hold on time for each selected event to be checked in the data source
            PROCTREE_HOLD_TIME=$(get_test_sleep TEST_CONFIG_MAP "PROCTREE_DATA_SOURCE")
            PROCTREE_HOLD_TIME=$((PROCTREE_HOLD_TIME / 2))
            if [[ ${PROCTREE_HOLD_TIME} -lt 5 ]]; then
                PROCTREE_HOLD_TIME=5
                info "PROCTREE_HOLD_TIME is too low, setting to 5 seconds"
            fi
            export PROCTREE_HOLD_TIME
            ;;

        VFS_WRITE)
            info "compiling vfs write test..."
            if ! ./tests/e2e-inst-signatures/scripts/vfs_writev.sh --build; then
                error "could not compile vfs_writev"
            fi
            ;;
    esac

    print_test_separator
done

print_test_header "START TRACE"

./scripts/tracee_start.sh \
    -i "${TRACEE_TMP_DIR}" \
    -o "${outputfile}" \
    -l "${logfile}" \
    -L debug \
    -t "${TRACEE_STARTUP_TIMEOUT}" \
    -- \
    --signatures-dir "${SIG_DIR}" \
    --output option:sort-events \
    --output option:parse-arguments \
    --proctree source=both \
    --dnscache enable \
    --server grpc-address=unix:/tmp/tracee.sock \
    --policy "${TRACEE_POLICY_PATH}"

last_status=$?
print_test_separator

if [[ ${last_status} -ne 0 ]]; then
    die "tracee startup failed"
fi

print_test_header "RUNNING TESTS"
declare -A test_pids_map=() # Map: test_name -> pid
max_internal_sleep=0
max_test_timeout=0

for TEST in ${TESTS}; do
    print_test_header "${TEST}" "RUNNING"

    # Check for skip conditions first
    if should_skip_test "${TEST}"; then
        info "skipping ${TEST}"
        print_test_separator
        continue
    fi

    test_timeout=$(get_test_timeout TEST_CONFIG_MAP "${TEST}")
    test_sleep=$(get_test_sleep TEST_CONFIG_MAP "${TEST}")

    # Track maximum internal sleep time and timeout
    if [[ "${test_sleep}" -gt "${max_internal_sleep}" ]]; then
        max_internal_sleep="${test_sleep}"
    fi
    if [[ "${test_timeout}" -gt "${max_test_timeout}" ]]; then
        max_test_timeout="${test_timeout}"
    fi

    # Set test arguments and run test
    test_args=""
    case ${TEST} in
        HOOKED_SYSCALL)
            info "unloading hijack module that was loaded at setup step"
            test_args="--uninstall"
            ;;
        FTRACE_HOOK)
            info "loading and unloading ftrace hook module"
            test_args="--install --uninstall"
            ;;
        *)
            case ${TEST} in
                CONTAINERS_DATA_SOURCE | \
                    BPF_ATTACH | \
                    SUSPICIOUS_SYSCALL_SOURCE | \
                    STACK_PIVOT | \
                    WRITABLE_DATA_SOURCE | \
                    SECURITY_PATH_NOTIFY | \
                    PROCTREE_DATA_SOURCE | \
                    VFS_WRITE)
                    test_args="--run"
                    ;;
            esac

            run_msg="running test ${TEST} with timeout ${test_timeout}"
            if [[ "${test_sleep}" -gt 0 ]]; then
                run_msg="${run_msg} and internal sleep ${test_sleep}"
            fi
            info "${run_msg}"
            ;;
    esac

    # Run test in background and store PID in map
    # Redirect output to file to show later during wait phase
    test_output_file="/tmp/test_${TEST,,}_$$"
    (
        # shellcheck disable=SC2086
        E2E_INST_TEST_SLEEP="${test_sleep}" timeout --preserve-status "${test_timeout}" "${TESTS_DIR}"/"${TEST,,}".sh ${test_args:-}
    ) > "${test_output_file}" 2>&1 &
    test_pids_map["${TEST}"]=$!

    print_test_separator
done

print_test_header "WAITING FOR TESTS TO COMPLETE"
info "Waiting for all tests to complete (max timeout: ${max_test_timeout}s, max internal sleep: ${max_internal_sleep}s)..."

# Wait for all test processes
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

    # Only show output if file has content
    if [[ -s "${test_output_file}" ]]; then
        info "  Output from ${test_name} test:"
        while IFS= read -r line; do
            info "    ${line}"
        done < "${test_output_file}"
    fi
    rm -f "${test_output_file}"

    # Extract PROCTREE_DATA_SOURCE signature logs from Tracee log file
    # This is an exceptional case: debugging PROCTREE_DATA_SOURCE is complex, so we display
    # signature-specific logs to aid diagnosis and keep all output (trigger and signature logs)
    # in one place. In the future, this could be removed if we find a better way to debug this test.
    if [[ "${test_name}" == "PROCTREE_DATA_SOURCE" && -f "${logfile}" ]]; then
        signature_logs=$(grep '\[e2eProcessTreeDataSource\]' "${logfile}" 2> /dev/null || true)
        if [[ -n "${signature_logs}" ]]; then
            info "  PROCTREE_DATA_SOURCE signature logs from Tracee:"
            while IFS= read -r line; do
                info "    ${line}"
            done <<< "${signature_logs}"
        fi
    fi
done
print_test_separator

# Wait for all events to be processed and signatures to complete.
print_test_header "WAIT FOR EVENTS TO BE PROCESSED"
# All tests are already managed by timeout command, so we just wait for more 5 seconds for event processing
info "Waiting for more 5 seconds for event processing"
sleep 5
print_test_separator

print_test_header "STOP TRACE"
# Stop tracee
# Make sure we exit tracee before checking output and log files
./scripts/tracee_stop.sh \
    -i "${TRACEE_TMP_DIR}" \
    -t "${TRACEE_SHUTDOWN_TIMEOUT}"

last_status=$?
print_test_separator

# Check if tracee shutdown failed
if [[ ${last_status} -ne 0 ]]; then
    die "tracee shutdown failed, trying to check for results may be misleading"
fi

print_test_header "CHECKING TESTS RESULTS"
anyerror=""
# Check if the test has failed or not
for TEST in ${TESTS}; do
    found=0 # Initialize for each test iteration

    print_test_header "${TEST}" "CHECKING"

    # Check for skip conditions
    if should_skip_test "${TEST}"; then
        info "skipped ${TEST} test"
        print_test_separator
        continue
    fi

    policy_name=$(get_policy_name TEST_CONFIG_MAP "${TEST}")

    # Get match count for all non skipped tests
    match_count=$(get_event_match_count "${outputfile}" "${TEST}" "${policy_name}")
    info "Found ${match_count} matching ${TEST} events with policy ${policy_name}"

    # Check for multi-policy matches (only if we have matches)
    # This is a safeguard to detect if the event is matched by multiple policies
    if [[ "${match_count}" -gt 0 ]]; then
        check_multi_policy_matches "${outputfile}" "${TEST}" "${policy_name}"
    fi

    # Determine success based on test type
    found=0

    # Special case: LSM_TEST when not supported
    if [[ "${TEST}" == "LSM_TEST" && "${lsm_test_not_supported}" -eq 1 ]]; then
        # LSM not supported - check for probe cancellation instead of events
        if grep -q "Probe failed due to incompatible probe" "${logfile}" \
            && grep -q 'Failing event.*lsm_test' "${logfile}"; then
            # Verify event is not present in output (should not be)
            if [[ "${match_count}" -eq 0 ]]; then
                found=1
                info "LSM not supported: verified probe cancellation and event not present"
            else
                info "LSM not supported: probe cancellation found, but event present in output (unexpected)"
            fi
        else
            info "LSM not supported: probe cancellation message not found"
        fi
    else
        # Standard case: success means we found matching events
        if [[ "${match_count}" -gt 0 ]]; then
            found=1
        fi
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

# Cleanup test artifacts
cleanup_test_artifact_files "${KEEP_ARTIFACTS}" "${outputfile}" "${logfile}"
rm -rf "${TRACEE_TMP_DIR}"

# Print summary and exit with error if any test failed
info
if [[ "${anyerror}" != "" ]]; then
    die "FAILED TESTS: ${anyerror::-1}"
fi

info "ALL TESTS PASSED"
exit 0
