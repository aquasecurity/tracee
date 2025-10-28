#!/bin/bash

#
# This test is executed by github workflows inside the action runners
#

ARCH=$(uname -m)

TRACEE_STARTUP_TIMEOUT=30
TRACEE_SHUTDOWN_TIMEOUT=30
SCRIPT_TMP_DIR=/tmp
TRACEE_TMP_DIR=/tmp/tracee

# Default test to run if no other is given
TESTS=${INSTTESTS:=VFS_WRITE CONTAINERS_DATA_SOURCE WRITABLE_DATA_SOURCE DNS_DATA_SOURCE PROCTREE_DATA_SOURCE PROCESS_EXECUTE_FAILED LSM_TEST}

TRACEE_POLICY_PATH="./tests/policies/inst/"

# Test configuration: policy_name:timeout:internal_sleep
declare -A TEST_CONFIG_MAP=(
    ["SET_FS_PWD"]="set-fs-pwd-test:5:0"                             # set_fs_pwd.sh: timeout 5s, no sleep
    ["WRITABLE_DATA_SOURCE"]="writable-ds-test:40:0"                 # writable_data_source.sh: timeout 40s, no sleep
    ["SECURITY_PATH_NOTIFY"]="security-path-notify-test:5:0"         # security_path_notify.sh: timeout 5s, no sleep
    ["SUSPICIOUS_SYSCALL_SOURCE"]="suspicious-syscall-src-test:10:0" # suspicious_syscall_source.sh: timeout 10s, no sleep
    ["CONTAINERS_DATA_SOURCE"]="containers-ds-test:10:5"             # containers_data_source.sh: timeout 10s, container sleeps 5s
    ["PROCTREE_DATA_SOURCE"]="proctree-ds-test:20:15"                # proctree_data_source.sh: timeout 20s, proctreetester program sleeps 15s
    ["HOOKED_SYSCALL"]="hooked-syscall-test:10:5"                    # hooked_syscall.sh: timeout 10s, script sleeps 5s
    ["PROCESS_EXECUTE_FAILED"]="execute-failed-test:5:2"             # process_execute_failed.sh: timeout 5s, script sleeps 2s
    ["STACK_PIVOT"]="stack-pivot-test:10:5"                          # stack_pivot.sh: timeout 10s, stack_pivot program sleeps 5s
    ["FTRACE_HOOK"]="ftrace-hook-test:15:5"                          # ftrace_hook.sh: timeout 15s, script sleeps 5s
    ["BPF_ATTACH"]="bpf-attach-test:15:5"                            # bpf_attach.sh: timeout 15s, script sleeps 5s
    ["DNS_DATA_SOURCE"]="dns-ds-test:10:0"                           # dns_data_source.sh: timeout 10s, no sleep
    ["SECURITY_INODE_RENAME"]="security-inode-rename-test:10:2"      # security_inode_rename.sh: timeout 10s, script sleeps 2s
    ["FILE_MODIFICATION"]="file-modification-test:5:0"               # file_modification.sh: timeout 5s, no sleep
    ["LSM_TEST"]="lsm-test:5:0"                                      # lsm_test.sh: timeout 5s, no sleep
    ["VFS_WRITE"]="vfs-write-test:5:0"                               # vfs_writev.sh: timeout 5s, no sleep
)

# Helper functions to extract config values
get_policy_name() {
    local test_name="$1"
    echo "${TEST_CONFIG_MAP[$test_name]}" | cut -d: -f1
}

get_test_timeout() {
    local test_name="$1"
    echo "${TEST_CONFIG_MAP[$test_name]}" | cut -d: -f2
}

get_test_sleep() {
    local test_name="$1"
    echo "${TEST_CONFIG_MAP[$test_name]}" | cut -d: -f3
}

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

info_exit() {
    echo -n "INFO: "
    echo "$@"
    exit 0
}

info() {
    echo -n "INFO: "
    echo "$@"
}

error() {
    echo -n "ERROR: "
    echo "$@"
}

error_exit() {
    error "$@"
    exit 1
}

# Function to generate repeated characters for given width
generate_chars() {
    local char="$1"
    local count="$2"
    printf "%${count}s" | tr ' ' "$char"
}

# Function to print end separator line
print_end_separator() {
    local total_width=80
    local underscores
    underscores=$(generate_chars '-' "$total_width")
    info "${underscores}"
    info
}

# Function to print test header
print_test_header() {
    local test_name="$1"
    local action="${2:-}"
    local total_width=80
    local header_text

    if [[ -z "$action" ]]; then
        # main section headers
        header_text="= ${test_name} "
    else
        # individual test headers
        header_text="= ${action} TEST: ${test_name} "
    fi

    # calculate number of characters needed
    local text_length=${#header_text}
    local equals_needed=$((total_width - text_length))

    # generate the characters
    local equals_string
    equals_string=$(generate_chars '=' "$equals_needed")

    info "${header_text}${equals_string}"
    info
}

# Function to filter logs and show only WARN, ERROR, FATAL levels
filter_critical_logs() {
    local logfile="$1"
    if [[ -f "${logfile}" ]]; then
        grep -E "(WARN|ERROR|FATAL)" "${logfile}" || echo "No WARN, ERROR, or FATAL logs found"
    else
        echo "Log file not found: ${logfile}"
    fi
}

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
    error_exit "need root privileges"
fi

if [[ ! -d ./signatures ]]; then
    error_exit "need to be in tracee root directory"
fi

rm -rf ${TRACEE_TMP_DIR:?}/* || error_exit "could not delete ${TRACEE_TMP_DIR}"

KERNEL=$(uname -r)
KERNEL_MAJ=$(echo "${KERNEL}" | cut -d'.' -f1)

if [[ ${KERNEL_MAJ} -lt 5 && "${KERNEL}" != *"el8"* ]]; then
    info_exit "skip test in kernels < 5.0 (and not RHEL)"
fi

SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
TESTS_DIR="$SCRIPT_DIR/e2e-inst-signatures/scripts"
SIG_DIR="$SCRIPT_DIR/../dist/e2e-inst-signatures"

print_test_header "ENVIRONMENT"
info "KERNEL: ${KERNEL}"
info "CLANG: $(clang --version)"
info "GO: $(go version)"
print_end_separator

print_test_header "COMPILING TRACEE"
# make clean # if you want to be extra cautious
set -e
make -j"$(nproc)" all
make e2e-inst-signatures
set +e
print_end_separator

# check if tracee was built correctly
if [[ ! -x ./dist/tracee ]]; then
    error_exit "could not find tracee executable"
fi

logfile=${SCRIPT_TMP_DIR}/tracee-log-$$
outputfile=${SCRIPT_TMP_DIR}/output-$$

# remove old log and output files
rm -f ${outputfile}
rm -f ${logfile}

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
            if ./dist/lsm-check -q; then
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
            # Set up log file for retry information
            export PROCTREE_RETRY_LOG_FILE="${SCRIPT_TMP_DIR}/proctree_retries_$$"
            ;;

        VFS_WRITE)
            info "compiling vfs write test..."
            if ! ./tests/e2e-inst-signatures/scripts/vfs_writev.sh --build; then
                error "could not compile vfs_writev"
            fi
            ;;
    esac

    print_end_separator
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
print_end_separator

if [[ ${last_status} -ne 0 ]]; then
    error_exit "tracee startup failed"
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
        print_end_separator
        continue
    fi

    test_timeout=$(get_test_timeout "${TEST}")
    test_sleep=$(get_test_sleep "${TEST}")
    export E2E_INST_TEST_SLEEP="${test_sleep}" # test will use this env variable for sleeping

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
        timeout --preserve-status "${test_timeout}" "${TESTS_DIR}"/"${TEST,,}".sh ${test_args:-}
    ) > "${test_output_file}" 2>&1 &
    test_pids_map["${TEST}"]=$!

    print_end_separator
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
        info "Test ${test_name} completed with errors"
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

    # Show retry information for PROCTREE_DATA_SOURCE test
    if [[ "${test_name}" == "PROCTREE_DATA_SOURCE" &&
        -n "${PROCTREE_RETRY_LOG_FILE}" &&
        -f "${PROCTREE_RETRY_LOG_FILE}" ]]; then
        #
        info "  Process tree retry information:"
        while IFS= read -r line; do
            info "    ${line}"
        done < "${PROCTREE_RETRY_LOG_FILE}"
        rm -f "${PROCTREE_RETRY_LOG_FILE}"
    fi 
done
print_end_separator

# Wait for all events to be processed and signatures to complete.
print_test_header "WAIT FOR EVENTS TO BE PROCESSED"
# All tests are already managed by timeout command, so we just wait for more 5 seconds for event processing
info "Waiting for more 5 seconds for event processing"
sleep 5
print_end_separator

print_test_header "STOP TRACE"
# Stop tracee
# Make sure we exit tracee before checking output and log files
./scripts/tracee_stop.sh \
    -i "${TRACEE_TMP_DIR}" \
    -t "${TRACEE_SHUTDOWN_TIMEOUT}"

last_status=$?
print_end_separator

# Check if tracee shutdown failed
if [[ ${last_status} -ne 0 ]]; then
    error_exit "tracee shutdown failed, trying to check for results may be misleading"
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
        print_end_separator
        continue
    fi

    policy_name=$(get_policy_name "${TEST}")

    # get match count for all non skipped tests
    match_count=$(jq -s \
        --arg event "${TEST}" \
        --arg policy "${policy_name}" \
        '
        [.[] | 
         select(.eventName == $event and (.matchedPolicies[]? == $policy))
        ] | length
        ' \
        "${outputfile}")
    info "Found ${match_count} matching ${TEST} events with policy ${policy_name}"

    # Check for multi-policy matches (only if we have matches)
    # This is a safeguard to detect if the event is matched by multiple policies
    if [[ "${match_count}" -gt 0 ]]; then
        multi_policy_output=$(jq -s \
            --arg event "${TEST}" \
            --arg policy "${policy_name}" \
            -r \
            '
            [.[] | 
             select(.eventName == $event and 
                    (.matchedPolicies[]? == $policy) and 
                    (.matchedPolicies | length > 1))
            ] |
            .[] | "  Timestamp: \(.timestamp) | Event: \(.eventName) | Policies: \(.matchedPolicies | join(", "))"
            ' \
            "${outputfile}")

        if [[ -n "${multi_policy_output}" ]]; then
            multi_policy_count=$(echo "${multi_policy_output}" | wc -l)
            info "Found ${multi_policy_count} events that matched multiple policies:"
            while IFS= read -r line; do
                info "${line}"
            done <<< "${multi_policy_output}"
        fi
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
    print_end_separator
done

info

# Cleanup leftovers
if [[ ${KEEP_ARTIFACTS} -eq 0 ]]; then
    rm -f "${outputfile}"
    rm -f "${logfile}"
else
    info "Test artifacts preserved:"
    info "  Output file: ${outputfile}"
    info "  Log file: ${logfile}"
fi
rm -rf ${TRACEE_TMP_DIR}

# Print summary and exit with error if any test failed

info
if [[ "${anyerror}" != "" ]]; then
    info "FAILED TESTS: ${anyerror::-1}"
    exit 1
fi

info "ALL TESTS PASSED"
exit 0
