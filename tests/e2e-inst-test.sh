#!/bin/bash

#
# This test is executed by github workflows inside the action runners
#

ARCH=$(uname -m)

TRACEE_STARTUP_TIMEOUT=30
TRACEE_SHUTDOWN_TIMEOUT=30
TRACEE_RUN_TIMEOUT=60
SCRIPT_TMP_DIR=/tmp
TRACEE_TMP_DIR=/tmp/tracee

# Default test to run if no other is given
TESTS=${INSTTESTS:=VFS_WRITE CONTAINERS_DATA_SOURCE WRITABLE_DATA_SOURCE DNS_DATA_SOURCE PROCTREE_DATA_SOURCE PROCESS_EXECUTE_FAILED LSM_TEST}

# Command line options
KEEP_ARTIFACTS=0

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-artifacts)
            KEEP_ARTIFACTS=1
            shift
            ;;
        -h|--help)
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

error_exit() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

# Function to filter logs and show only WARN, ERROR, FATAL levels
filter_critical_logs() {
    local logfile="$1"
    if [[ -f "$logfile" ]]; then
        grep -E "(WARN|ERROR|FATAL)" "$logfile" || echo "No WARN, ERROR, or FATAL logs found"
    else
        echo "Log file not found: $logfile"
    fi
}

if [[ $UID -ne 0 ]]; then
    error_exit "need root privileges"
fi

. /etc/os-release

if [[ ! -d ./signatures ]]; then
    error_exit "need to be in tracee root directory"
fi

rm -rf ${TRACEE_TMP_DIR:?}/* || error_exit "could not delete $TRACEE_TMP_DIR"

KERNEL=$(uname -r)
KERNEL_MAJ=$(echo "$KERNEL" | cut -d'.' -f1)

if [[ $KERNEL_MAJ -lt 5 && "$KERNEL" != *"el8"* ]]; then
    info_exit "skip test in kernels < 5.0 (and not RHEL)"
fi

SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
TESTS_DIR="$SCRIPT_DIR/e2e-inst-signatures/scripts"
SIG_DIR="$SCRIPT_DIR/../dist/e2e-inst-signatures"

git config --global --add safe.directory "*"

info
info "= ENVIRONMENT ================================================="
info
info "KERNEL: ${KERNEL}"
info "CLANG: $(clang --version)"
info "GO: $(go version)"
info
info "= COMPILING TRACEE ============================================"
info
# make clean # if you want to be extra cautious
set -e
make -j"$(nproc)" all
make e2e-inst-signatures
set +e

# Check if tracee was built correctly

if [[ ! -x ./dist/tracee ]]; then
    error_exit "could not find tracee executable"
fi

logfile=$SCRIPT_TMP_DIR/tracee-log-$$
outputfile=$SCRIPT_TMP_DIR/output-$$

 # Run tracee

rm -f $outputfile
rm -f $logfile

skip_hooked_syscall=0
skip_ftrace_hook=0
skip_security_path_notify=0
skip_suspicious_syscall_source=0
skip_stack_pivot=0
lsm_test_not_supported=0

# Setup tests and skips
# Some tests might need special setup (like running before tracee)

for TEST in $TESTS; do
    case $TEST in
    HOOKED_SYSCALL)
        if [[ ! -d /lib/modules/${KERNEL}/build ]]; then
            info "skip hooked_syscall test, no kernel headers"
            skip_hooked_syscall=1
            continue
        fi
        if [[ "$KERNEL" == *"amzn"* ]]; then
            info "skip hooked_syscall test in amazon linux"
            skip_hooked_syscall=1
            continue
        fi
        if [[ $ARCH == "aarch64" ]]; then
            info "skip hooked_syscall test in aarch64"
            skip_hooked_syscall=1
            continue
        fi
        info "setting up hooked_syscall test"
        "${TESTS_DIR}"/hooked_syscall.sh
        ;;
    FTRACE_HOOK)
        if [[ ! -d /lib/modules/${KERNEL}/build ]]; then
            info "skip ftrace_hook test, no kernel headers"
            skip_ftrace_hook=1
            continue
        fi
        if [[ "$KERNEL" == *"amzn"* ]]; then
            info "skip ftrace_hook test in amazon linux"
            skip_ftrace_hook=1
            continue
        fi
        if [[ $ARCH == "aarch64" ]]; then
            info "skip ftrace_hook test in aarch64"
            skip_ftrace_hook=1
            continue
        fi
        info "setting up ftrace_hook test"
        "${TESTS_DIR}"/ftrace_hook.sh
        ;;
    SECURITY_PATH_NOTIFY)
        if ! grep -qw "security_path_notify" /proc/kallsyms; then
            info "skip security_path_notify test on kernel $(uname -r) (security hook doesn't exist)"
            skip_security_path_notify=1
            continue
        fi
        ;;
    SUSPICIOUS_SYSCALL_SOURCE|STACK_PIVOT)
        if cat /proc/kallsyms | grep -qP "trace.*vma_store"; then
            info "skip $TEST test on kernel $(uname -r) (VMAs stored in maple tree)"
            skip_suspicious_syscall_source=1
            skip_stack_pivot=1
            continue
        fi
        ;;
    LSM_TEST)
        # Test LSM BPF support using Tracee's actual BPF loading test
        info "testing LSM BPF support using actual BPF loading..."
        if ./dist/lsm-check -q; then
            info "LSM BPF support confirmed - test will run normally"
        else
            info "skip lsm_test on kernel $(uname -r) (LSM BPF not supported)"
            lsm_test_not_supported=1
            continue
        fi
        ;;
    esac
done

tracee_command="./dist/tracee \
                    --general workdir=$TRACEE_TMP_DIR \
                    --stores process.enabled=true --stores process.source=both \
                    --output option:sort-events \
                    --output option:parse-arguments \
                    --output json:$outputfile \
                    --log level=debug \
                    --log file=$logfile \
                    --signatures search-paths=$SIG_DIR \
                    --stores dns.enabled=true \
                    --server grpc-address=unix:/tmp/tracee.sock \
                    --policy ./tests/policies/inst/"


eval "$tracee_command &"

# Wait tracee to start

times=0
timedout=0
while true; do
    times=$((times + 1))
    sleep 1
    if [[ -f $TRACEE_TMP_DIR/tracee.pid ]]; then
        info
        info "UP AND RUNNING"
        info
        break
    fi

    if [[ $times -gt $TRACEE_STARTUP_TIMEOUT ]]; then
        timedout=1
        break
    fi
done

# Tracee failed to start

if [[ $timedout -eq 1 ]]; then
    info
    info "$TEST: timed out"
    info "$TEST: FAILED. ERRORS:"
    info
    anyerror="${anyerror}$TEST,"
    filter_critical_logs "$logfile"

    exit 1
fi

# Allow tracee to start processing events

sleep 3

info "= RUNNING TESTS ================================================"
info
# Run tests, one by one

for TEST in $TESTS; do

    info
    info "= TEST: $TEST =============================================="
    info

    case $TEST in
    HOOKED_SYSCALL)
        # wait for tracee hooked event to be processed
        info "waiting for tracee hooked event to be processed"
        sleep 15
        ;;
    FTRACE_HOOK)
        info "waiting for tracee ftrace hook event to be processed"
        sleep 15
        ;;
    *)
        info "running test $TEST"
        timeout --preserve-status $TRACEE_RUN_TIMEOUT "${TESTS_DIR}"/"${TEST,,}".sh
        ;;
    esac
done


# So events can finish processing
sleep 5

# Stop tracee
# Make sure we exit tracee before checking output and log files

mapfile -t tracee_pids < <(pgrep -x tracee)
kill -SIGINT "${tracee_pids[@]}"
sleep $TRACEE_SHUTDOWN_TIMEOUT
kill -SIGKILL "${tracee_pids[@]}" >/dev/null 2>&1

anyerror=""
info "= CHECKING TESTS RESULTS ======================================"
info
# Check if the test has failed or not
for TEST in $TESTS; do
    found=0  # Initialize for each test iteration

    if [[ $skip_hooked_syscall -eq 1 && $TEST == "HOOKED_SYSCALL" ]]; then
        info "skipped $TEST test"
        continue
    fi
    if [[ $skip_ftrace_hook -eq 1 && $TEST == "FTRACE_HOOK" ]]; then
        info "skipped $TEST test"
        continue
    fi
    if [[ $skip_security_path_notify -eq 1 && $TEST == "SECURITY_PATH_NOTIFY" ]]; then
        info "skipped $TEST test"
        continue
    fi
    if [[ $skip_suspicious_syscall_source -eq 1 && $TEST == "SUSPICIOUS_SYSCALL_SOURCE" ]]; then
        info "skipped $TEST test"
        continue
    fi
    if [[ $skip_stack_pivot -eq 1 && $TEST == "STACK_PIVOT" ]]; then
        info "skipped $TEST test"
        continue
    fi
    if [[ $lsm_test_not_supported -eq 1 && $TEST == "LSM_TEST" ]]; then
        # LSM not supported - check for probe cancellation instead of events
        found=0
        if grep -q "Probe failed due to incompatible probe" $logfile && \
           grep -q 'Failing event.*lsm_test' $logfile; then
            # Verify event is not present in output (should not be)
            if ! cat $outputfile | jq .eventName | grep -q "$TEST"; then
                found=1
                info "LSM not supported: verified probe cancellation and event not present"
            else
                info "LSM not supported: probe cancellation found, but event present in output (unexpected)"
            fi
        else
            info "LSM not supported: probe cancellation message not found"
        fi
    else
        # Normal test: look for events in output
        cat $outputfile | jq .eventName | grep -q "$TEST" && found=1
    fi
    
    errors=$(cat $logfile | wc -l 2>/dev/null)

    if [[ $TEST == "BPF_ATTACH" ]]; then
        errors=0
    fi

    info
    if [[ $found -eq 1 ]]; then
        info "$TEST: SUCCESS"
    else
        anyerror="${anyerror}$TEST,"

        info "$TEST: FAILED, critical logs from tracee:"
        filter_critical_logs "$logfile"

        info "$TEST: FAILED, events from tracee:"
        cat $outputfile

        info "Tracee command:"
        echo "$tracee_command" | tr -s ' '

        info "Tracee process is running?"
        mapfile -t tracee_pids < <(pgrep -x tracee)
        if [[ -n "${tracee_pids[*]}" ]]; then
            info "YES, Tracee is still running (should not be, fix me!), pids: ${tracee_pids[*]}"
            info "Aborting tests"
            break
        else
            info "NO, Tracee is not running, as expected"
        fi
        info
    fi
    info
done

# Cleanup leftovers
if [[ $KEEP_ARTIFACTS -eq 0 ]]; then
    rm -f $outputfile
    rm -f $logfile
else
    info "Test artifacts preserved:"
    info "  Output file: $outputfile"
    info "  Log file: $logfile"
fi
rm -rf $TRACEE_TMP_DIR

# Print summary and exit with error if any test failed

info
if [[ $anyerror != "" ]]; then
    info "ALL TESTS: FAILED: ${anyerror::-1}"
    exit 1
fi

info "ALL TESTS: SUCCESS"

exit 0
