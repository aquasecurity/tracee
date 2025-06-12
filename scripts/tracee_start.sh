#!/bin/sh

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "${SCRIPT_DIR}/tracee_common.sh"

require_cmds cat realpath sleep

# Default values specific to start script
TRACEE_BIN_DEFAULT=$(realpath "${SCRIPT_DIR}/../dist/tracee" 2> /dev/null \
    || printf "%s" "${SCRIPT_DIR}/../dist/tracee")
TIMEOUT_DEFAULT=30
EVENT_OUTPUT_FILE_DEFAULT="events.json"
LOG_OUTPUT_FILE_DEFAULT="log.json"
LOG_LEVEL_DEFAULT="info"

show_help() {
    cat << EOF
Usage: $0 [OPTIONS] [-- ADDITIONAL_TRACEE_ARGS]

Options:
    --bin, -b PATH           Path to tracee binary (default: ${TRACEE_BIN_DEFAULT})
    --install-path, -i PATH  Installation path for tracee (default: ${TRACEE_INSTALL_PATH_DEFAULT})
    --output-file, -o FILE   Output file for events in JSON format (default: <install-path>/${EVENT_OUTPUT_FILE_DEFAULT})
    --log-file, -l FILE      Output file for logs in JSON format (default: <install-path>/${LOG_OUTPUT_FILE_DEFAULT})
    --log-level, -L LEVEL    Log level (default: ${LOG_LEVEL_DEFAULT})
    --timeout, -t SECONDS    Timeout to wait for tracee startup (default: ${TIMEOUT_DEFAULT})
    --help, -h               Show this help message

Note: All outputs are automatically configured in JSON format.
      
      The script manages install-path, output, and log flags internally before passing them to tracee.
      Do not pass --install-path, --output or --log flags as additional arguments as they will conflict
      with the script's managed flags and may cause Tracee to behave unexpectedly.
      
      Other tracee-specific arguments like -e (events), -p (policies), -s (scope), etc. should be
      passed as additional arguments.

Examples:
    $0 -e "execve,openat"
    $0 -p "/tmp/policies"
    $0 -p "/tmp/policies/policy1.yaml,/tmp/policies/policy2.yaml" --timeout 60
    $0 --bin ~/bin/tracee --install-path /tmp/tracee_install -e "openat"
    $0 -e openat -s comm=uname
    $0 -- -e "openat" -s comm=uname --some-other-flag
EOF
}

# Parse command line arguments
ADDITIONAL_ARGS=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin | -b)
            TRACEE_BIN="$2"
            shift 2
            ;;
        --install-path | -i)
            TRACEE_INSTALL_PATH="$2"
            shift 2
            ;;
        --output-file | -o)
            EVENT_OUTPUT_FILE="$2"
            shift 2
            ;;
        --log-file | -l)
            LOG_OUTPUT_FILE="$2"
            shift 2
            ;;
        --log-level | -L)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --timeout | -t)
            TIMEOUT="$2"
            shift 2
            ;;
        --help | -h)
            show_help
            exit 0
            ;;
        --)
            # Everything after -- goes to tracee
            shift
            ADDITIONAL_ARGS="$*"
            break
            ;;
        *)
            # Collect unrecognized arguments to pass to tracee
            if [ -z "${ADDITIONAL_ARGS}" ]; then
                ADDITIONAL_ARGS="$1"
            else
                ADDITIONAL_ARGS="${ADDITIONAL_ARGS} $1"
            fi
            shift
            ;;
    esac
done

# Set defaults using parameter expansion, ensuring TRACEE_BIN is absolute
TRACEE_BIN="${TRACEE_BIN:-${TRACEE_BIN_DEFAULT}}"
TRACEE_BIN=$(realpath "${TRACEE_BIN}" 2> /dev/null \
    || printf "%s" "${TRACEE_BIN}")
TIMEOUT="${TIMEOUT:-${TIMEOUT_DEFAULT}}"

# Setup common paths
setup_tracee_paths

# Set up output files based on install path
EVENT_OUTPUT_FILE="${EVENT_OUTPUT_FILE:-${TRACEE_INSTALL_PATH}/${EVENT_OUTPUT_FILE_DEFAULT}}"
LOG_OUTPUT_FILE="${LOG_OUTPUT_FILE:-${TRACEE_INSTALL_PATH}/${LOG_OUTPUT_FILE_DEFAULT}}"
LOG_LEVEL="${LOG_LEVEL:-${LOG_LEVEL_DEFAULT}}"

cleanup() {
    info "Cleaning up ..."

    tracee_pid=$(get_tracee_pid_from_pidfile nofail)
    if [ -n "${tracee_pid}" ]; then
        kill -TERM "${tracee_pid}" 2> /dev/null || true
        cleanup_count=10
        while [ ${cleanup_count} -gt 0 ]; do
            sleep 1
            if [ ! -d "/proc/${tracee_pid}" ]; then
                break
            fi
            cleanup_count=$((cleanup_count - 1))
        done

        if [ -d "/proc/${tracee_pid}" ]; then
            warn "Process ${tracee_pid} didn't terminate gracefully, using SIGKILL"
            kill -KILL "${tracee_pid}" 2> /dev/null || true
        fi

        cleanup_tracee_pid_file

        sleep 5
    else
        info "No PID from PID file found to clean up"
    fi

    info "Cleaned up"
}
trap cleanup INT TERM

# Custom error handler for start script
handle_tracee_error() {
    error_msg="$1"

    error
    error "Log output ${LOG_OUTPUT_FILE}:"
    cat "${LOG_OUTPUT_FILE}" >&2 || true

    error
    error "Event output ${EVENT_OUTPUT_FILE}:"
    cat "${EVENT_OUTPUT_FILE}" >&2 || true

    error
    die "Tracee failed to start: ${error_msg}"
}

#
# Main
#

set -e

# Check if tracee is already running
running_pids=$(check_tracee_running 2> /dev/null || echo "")

if [ -n "${running_pids}" ]; then
    error "Tracee is already running with PID(s): ${running_pids}"
    die "Stop the existing tracee instance first"
fi

# Check for stale PID file
if [ -f "${TRACEE_PIDFILE}" ]; then
    warn "Found stale PID file (no running tracee process)"
    info "Cleaning up stale PID file..."
    cleanup_tracee_pid_file
fi

info "Running Tracee"

rm -rf "${TRACEE_INSTALL_PATH}" || die "Failed to remove ${TRACEE_INSTALL_PATH}"

# Build tracee command based on configuration
output_flag="-o json:${EVENT_OUTPUT_FILE}"
log_flag="-l file:${LOG_OUTPUT_FILE}"
log_level_flag="-l ${LOG_LEVEL}"
install_flag="--install-path ${TRACEE_INSTALL_PATH}"

tracee_cmd="${TRACEE_BIN} \
${output_flag} \
${log_flag} \
${log_level_flag} \
${install_flag}"

# Add additional arguments if any were provided
if [ -n "${ADDITIONAL_ARGS}" ]; then
    tracee_cmd="${tracee_cmd} ${ADDITIONAL_ARGS}"
    debug "Additional arguments passed to tracee: ${ADDITIONAL_ARGS}"
fi

info "Start Tracee in the background"
info "Command: ${tracee_cmd}"
debug "Timeout: ${TIMEOUT} seconds"

# shellcheck disable=SC2086
eval "${tracee_cmd} &"

count=0
info "Wait up to ${TIMEOUT} seconds for the ${TRACEE_PIDFILE} to appear"
while [ ! -f "${TRACEE_PIDFILE}" ] && [ "${count}" -lt "${TIMEOUT}" ]; do
    sleep 1
    count=$((count + 1))
done

info "Elapsed time: ${count} seconds"

tracee_pid=$(get_tracee_pid_from_pidfile fail)
info "Tracee PID from file: ${tracee_pid}"

cooldown=5
info "Wait ${cooldown} seconds for Tracee to finish initializing"
sleep "${cooldown}"

info "Tracee successfully started"
info "To stop Tracee, run: ./scripts/tracee_stop.sh -i ${TRACEE_INSTALL_PATH}"
