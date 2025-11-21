#!/bin/bash
#
# Core E2E Instrumentation Test Implementations
#
# This file contains the implementation of core test phases:
#   - core_test_setup: Build/prepare core tests
#   - core_test_run: Execute core tests
#   - core_test_check: Validate core test results
#
# These functions are called by e2e-inst-test.sh coordinator.
#

# ==============================================================================
# Core Tests Available
# ==============================================================================
# List of all core tests that can be run
# This is the single source of truth for available core tests
# shellcheck disable=SC2034  # Used by coordinator script
INSTTESTS_CORE_AVAILABLE="
    LSM_TEST
    PROCESS_EXECUTE_FAILED
    VFS_WRITE
    FILE_MODIFICATION
    HOOKED_SYSCALL
    FTRACE_HOOK
    SECURITY_INODE_RENAME
    BPF_ATTACH
    CONTAINERS_DATA_SOURCE
    PROCTREE_DATA_SOURCE
    DNS_DATA_SOURCE
    WRITABLE_DATA_SOURCE
    SECURITY_PATH_NOTIFY
    SET_FS_PWD
    SUSPICIOUS_SYSCALL_SOURCE
    STACK_PIVOT
    IO_URING_EVENTS
"

# ==============================================================================
# Core Test Configuration
# ==============================================================================
# Initialize core test metadata
# Called by coordinator after validation, only if core tests will run
core_init_test_config() {
    add_test_config TEST_CONFIG_MAP "SET_FS_PWD" "set-fs-pwd-test" 5 0
    add_test_config TEST_CONFIG_MAP "WRITABLE_DATA_SOURCE" "writable-ds-test" 40 0
    add_test_config TEST_CONFIG_MAP "SECURITY_PATH_NOTIFY" "security-path-notify-test" 5 0
    add_test_config TEST_CONFIG_MAP "SUSPICIOUS_SYSCALL_SOURCE" "suspicious-syscall-src-test" 10 0
    add_test_config TEST_CONFIG_MAP "CONTAINERS_DATA_SOURCE" "containers-ds-test" 10 5
    add_test_config TEST_CONFIG_MAP "PROCTREE_DATA_SOURCE" "proctree-ds-test" 15 10
    add_test_config TEST_CONFIG_MAP "HOOKED_SYSCALL" "hooked-syscall-test" 10 5
    add_test_config TEST_CONFIG_MAP "PROCESS_EXECUTE_FAILED" "execute-failed-test" 5 2
    add_test_config TEST_CONFIG_MAP "STACK_PIVOT" "stack-pivot-test" 10 5
    add_test_config TEST_CONFIG_MAP "FTRACE_HOOK" "ftrace-hook-test" 15 5
    add_test_config TEST_CONFIG_MAP "BPF_ATTACH" "bpf-attach-test" 15 5
    add_test_config TEST_CONFIG_MAP "DNS_DATA_SOURCE" "dns-ds-test" 10 0
    add_test_config TEST_CONFIG_MAP "SECURITY_INODE_RENAME" "security-inode-rename-test" 10 2
    add_test_config TEST_CONFIG_MAP "FILE_MODIFICATION" "file-modification-test" 5 0
    add_test_config TEST_CONFIG_MAP "LSM_TEST" "lsm-test" 5 0
    add_test_config TEST_CONFIG_MAP "VFS_WRITE" "vfs-write-test" 5 0
}

# ==============================================================================
# Core Test Skip Management
# ==============================================================================
# Global skip flags - set by core_test_setup, read by core_should_skip_test
# Named with core_ prefix to avoid collisions and clarify ownership
# shellcheck disable=SC2034  # Set by core_test_setup below, read by core_should_skip_test
core_skip_hooked_syscall=0
# shellcheck disable=SC2034
core_skip_ftrace_hook=0
# shellcheck disable=SC2034
core_skip_security_path_notify=0
# shellcheck disable=SC2034
core_skip_suspicious_syscall_source=0
# shellcheck disable=SC2034
core_skip_stack_pivot=0
# shellcheck disable=SC2034
core_lsm_test_not_supported=0

# Check if a core test should be skipped
# Uses core_skip_* global flags set during core_test_setup
# Arguments:
#   $1 - Test name
# Returns:
#   0 - Test should be skipped
#   1 - Test should run
core_should_skip_test() {
    local test_name="$1"

    case "${test_name}" in
        HOOKED_SYSCALL)
            [[ "${core_skip_hooked_syscall:-0}" -eq 1 ]]
            ;;
        FTRACE_HOOK)
            [[ "${core_skip_ftrace_hook:-0}" -eq 1 ]]
            ;;
        SECURITY_PATH_NOTIFY)
            [[ "${core_skip_security_path_notify:-0}" -eq 1 ]]
            ;;
        SUSPICIOUS_SYSCALL_SOURCE)
            [[ "${core_skip_suspicious_syscall_source:-0}" -eq 1 ]]
            ;;
        STACK_PIVOT)
            [[ "${core_skip_stack_pivot:-0}" -eq 1 ]]
            ;;
        LSM_TEST)
            [[ "${core_lsm_test_not_supported:-0}" -eq 1 ]]
            ;;
        *)
            false
            ;;
    esac
}

# ==============================================================================
# Core Test Setup Phase
# ==============================================================================
# Build/prepare a single core test
# Arguments:
#   $1 - Test name
core_test_setup() {
    local test="$1"

    case ${test} in
        HOOKED_SYSCALL)
            # TODO: install kernel headers in the AMI images
            if [[ ! -d /lib/modules/${KERNEL}/build ]]; then
                info "skip hooked_syscall test, no kernel headers"
                core_skip_hooked_syscall=1
            fi
            if [[ "${KERNEL}" == *"amzn"* ]]; then
                info "skip hooked_syscall test in amazon linux"
                core_skip_hooked_syscall=1
            fi
            if [[ ${ARCH} == "aarch64" ]]; then
                info "skip hooked_syscall test in aarch64"
                core_skip_hooked_syscall=1
            fi
            if [[ "${core_skip_hooked_syscall}" -eq 0 ]]; then
                ./tests/e2e-inst-signatures/scripts/hooked_syscall.sh --build --install
            fi
            ;;

        FTRACE_HOOK)
            # TODO: install kernel headers in the AMI images
            if [[ ! -d /lib/modules/${KERNEL}/build ]]; then
                info "skip ftrace_hook test, no kernel headers"
                core_skip_ftrace_hook=1
            fi
            if [[ "${KERNEL}" == *"amzn"* ]]; then
                info "skip ftrace_hook test in amazon linux"
                core_skip_ftrace_hook=1
            fi
            if [[ ${ARCH} == "aarch64" ]]; then
                info "skip ftrace_hook test in aarch64"
                core_skip_ftrace_hook=1
            fi
            if [[ "${core_skip_ftrace_hook}" -eq 0 ]]; then
                ./tests/e2e-inst-signatures/scripts/ftrace_hook.sh --build
            fi
            ;;

        SECURITY_PATH_NOTIFY)
            if ! grep -qw "security_path_notify" /proc/kallsyms; then
                info "skip security_path_notify test on kernel ${KERNEL} (security hook doesn't exist)"
                core_skip_security_path_notify=1
            else
                info "compiling security path notify test..."
                if ! ./tests/e2e-inst-signatures/scripts/security_path_notify.sh --build; then
                    error "could not compile security_path_notify"
                fi
            fi
            ;;

        SUSPICIOUS_SYSCALL_SOURCE)
            if grep -qP "trace.*vma_store" /proc/kallsyms; then
                info "skip ${test} test on kernel ${KERNEL} (VMAs stored in maple tree)"
                core_skip_suspicious_syscall_source=1
            else
                info "compiling suspicious syscall source test..."
                if ! ./tests/e2e-inst-signatures/scripts/suspicious_syscall_source.sh --build; then
                    error "could not compile suspicious_syscall_source"
                fi
            fi
            ;;

        STACK_PIVOT)
            if grep -qP "trace.*vma_store" /proc/kallsyms; then
                info "skip ${test} test on kernel ${KERNEL} (VMAs stored in maple tree)"
                core_skip_stack_pivot=1
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
                core_lsm_test_not_supported=1
            elif ./dist/lsm-check -q; then
                info "LSM BPF support confirmed - test will run normally"
            else
                info "skip lsm_test on kernel ${KERNEL} (LSM BPF not supported)"
                core_lsm_test_not_supported=1
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
}

# ==============================================================================
# Core Test Run Phase
# ==============================================================================
# Execute a single core test in background
# Arguments:
#   $1 - Test name
#   $2 - Name of test_pids_map array (nameref)
#   $3 - Timeout in seconds
#   $4 - Sleep time in seconds
core_test_run() {
    local test="$1"
    local -n pid_map="$2"
    local timeout="$3"
    local sleep_time="$4"
    local test_args=""
    local run_msg=""

    case ${test} in
        HOOKED_SYSCALL)
            info "unloading hijack module that was loaded at setup step"
            test_args="--uninstall"
            ;;

        FTRACE_HOOK)
            info "loading and unloading ftrace hook module"
            test_args="--install --uninstall"
            ;;

        CONTAINERS_DATA_SOURCE | \
            BPF_ATTACH | \
            SUSPICIOUS_SYSCALL_SOURCE | \
            STACK_PIVOT | \
            WRITABLE_DATA_SOURCE | \
            SECURITY_PATH_NOTIFY | \
            PROCTREE_DATA_SOURCE | \
            VFS_WRITE)
            test_args="--run"

            run_msg="running test ${test} with timeout ${timeout}"
            if [[ "${sleep_time}" -gt 0 ]]; then
                run_msg="${run_msg} and internal sleep ${sleep_time}"
            fi
            info "${run_msg}"
            ;;
    esac

    # Execute test in background using common helper
    local test_script="${TESTS_DIR}/${test,,}.sh"
    run_test_background "${test}" "$2" "${timeout}" "${sleep_time}" "${test_script}" "${test_args}"
}

# ==============================================================================
# Core Test Check Phase
# ==============================================================================
# Validate a single core test result
# Arguments:
#   $1 - Test name
#   $2 - Path to output file
#   $3 - Path to log file
# Returns:
#   0 - Test passed
#   1 - Test failed
core_test_check() {
    local test="$1"
    local outputfile="$2"
    local logfile="$3"
    local policy_name
    local match_count

    # Get policy and match count for all core tests
    case ${test} in
        SET_FS_PWD | \
            WRITABLE_DATA_SOURCE | \
            SECURITY_PATH_NOTIFY | \
            SUSPICIOUS_SYSCALL_SOURCE | \
            CONTAINERS_DATA_SOURCE | \
            PROCTREE_DATA_SOURCE | \
            HOOKED_SYSCALL | \
            PROCESS_EXECUTE_FAILED | \
            STACK_PIVOT | \
            FTRACE_HOOK | \
            BPF_ATTACH | \
            DNS_DATA_SOURCE | \
            SECURITY_INODE_RENAME | \
            FILE_MODIFICATION | \
            VFS_WRITE)

            policy_name=$(get_policy_name TEST_CONFIG_MAP "${test}")
            match_count=$(get_event_match_count "${outputfile}" "${test}" "${policy_name}")
            info "Found ${match_count} matching ${test} events with policy ${policy_name}"

            # Check for multi-policy matches (only if we have matches)
            if [[ "${match_count}" -gt 0 ]]; then
                check_multi_policy_matches "${outputfile}" "${test}" "${policy_name}"
            fi

            # Standard case: success means we found matching events
            if [[ "${match_count}" -gt 0 ]]; then
                return 0
            else
                return 1
            fi
            ;;

        LSM_TEST)
            # Special case: LSM_TEST when not supported
            if [[ "${core_lsm_test_not_supported}" -eq 1 ]]; then
                # LSM not supported - check for probe cancellation instead of events
                if grep -q "Probe failed due to incompatible probe" "${logfile}" \
                    && grep -q 'Failing event.*lsm_test' "${logfile}"; then
                    # Get match count to verify event is not present
                    policy_name=$(get_policy_name TEST_CONFIG_MAP "${test}")
                    match_count=$(get_event_match_count "${outputfile}" "${test}" "${policy_name}")

                    if [[ "${match_count}" -eq 0 ]]; then
                        info "LSM not supported: verified probe cancellation and event not present"
                        return 0
                    else
                        info "LSM not supported: probe cancellation found, but event present in output (unexpected)"
                        return 1
                    fi
                else
                    info "LSM not supported: probe cancellation message not found"
                    return 1
                fi
            else
                # LSM supported - standard check
                policy_name=$(get_policy_name TEST_CONFIG_MAP "${test}")
                match_count=$(get_event_match_count "${outputfile}" "${test}" "${policy_name}")
                info "Found ${match_count} matching ${test} events with policy ${policy_name}"

                if [[ "${match_count}" -gt 0 ]]; then
                    check_multi_policy_matches "${outputfile}" "${test}" "${policy_name}"
                    return 0
                else
                    return 1
                fi
            fi
            ;;
    esac
}
