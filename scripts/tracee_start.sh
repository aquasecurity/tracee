#!/bin/sh

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "${SCRIPT_DIR}/tracee_common.sh"

require_cmds cat realpath setsid sleep

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
    --workdir, -w PATH       Working directory for tracee (default: ${TRACEE_WORKDIR_DEFAULT})
    --output-file, -o FILE   Output file for events in JSON format (default: <workdir>/${EVENT_OUTPUT_FILE_DEFAULT})
    --log-file, -l FILE      Output file for logs in JSON format (default: <workdir>/${LOG_OUTPUT_FILE_DEFAULT})
    --log-level, -L LEVEL    Log level (default: ${LOG_LEVEL_DEFAULT})
    --timeout, -t SECONDS    Timeout to wait for tracee startup (default: ${TIMEOUT_DEFAULT})
    --help, -h               Show this help message

Note: All outputs are automatically configured in JSON format.
      
      The script manages runtime workdir, output, and log flags internally before passing them to tracee.
      Do not pass --runtime workdir, --output or --log flags as additional arguments as they will conflict
      with the script's managed flags and may cause Tracee to behave unexpectedly.
      
      Other tracee-specific arguments like -e (events), -p (policies), -s (scope), etc. should be
      passed as additional arguments.

Examples:
    $0 -e "execve,openat"
    $0 -p "/tmp/policies"
    $0 -p "/tmp/policies/policy1.yaml,/tmp/policies/policy2.yaml" --timeout 60
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
        --workdir | -w)
            TRACEE_WORKDIR="$2"
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
            if [ -n "$2" ]; then
                error "Unrecognized option: $1 $2"
                error "Use '--' to pass arguments to tracee, e.g.: $0 -- $1 $2"
            else
                error "Unrecognized option: $1"
                error "Use '--' to pass arguments to tracee, e.g.: $0 -- $1"
            fi
            die "Run '$0 --help' for usage information"
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

# Set up output files based on workdir
EVENT_OUTPUT_FILE="${EVENT_OUTPUT_FILE:-${TRACEE_WORKDIR}/${EVENT_OUTPUT_FILE_DEFAULT}}"
LOG_OUTPUT_FILE="${LOG_OUTPUT_FILE:-${TRACEE_WORKDIR}/${LOG_OUTPUT_FILE_DEFAULT}}"
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

rm -rf "${TRACEE_WORKDIR}" || die "Failed to remove ${TRACEE_WORKDIR}"

# Build positional parameters for tracee execution
# This approach preserves argument boundaries correctly without needing eval
set -- "${TRACEE_BIN}" \
    "--output" "json:${EVENT_OUTPUT_FILE}" \
    "--logging" "file=${LOG_OUTPUT_FILE}" \
    "--logging" "level=${LOG_LEVEL}" \
    "--runtime" "workdir=${TRACEE_WORKDIR}"

# Add additional arguments if any were provided
if [ -n "${ADDITIONAL_ARGS}" ]; then
    debug "Additional arguments passed to tracee: ${ADDITIONAL_ARGS}"
    # Append ADDITIONAL_ARGS to positional parameters
    # Note: This uses word splitting on ADDITIONAL_ARGS, which is intentional
    # shellcheck disable=SC2086
    set -- "$@" ${ADDITIONAL_ARGS}
fi

info "Start Tracee in the background"
# Display the command that will be executed
info "Command: $*"
debug "Timeout: ${TIMEOUT} seconds"

# Start Tracee in a new session using setsid to properly daemonize it.
# This detaches from the controlling terminal and creates a new process session,
# which ensures proper signal handling and prevents zombie processes. When the
# parent shell exits, Tracee will be adopted by a session manager (systemd --user)
# or init (PID 1), which will properly reap the process. Without setsid, signaling
# the process for termination may not work correctly.
#
# Using "$@" here properly preserves argument boundaries, including arguments
# with spaces. The positional parameters were built using set -- above.
setsid "$@" &

count=0
info "Wait up to ${TIMEOUT} seconds for the ${TRACEE_PIDFILE} to appear"
while [ ! -f "${TRACEE_PIDFILE}" ] && [ "${count}" -lt "${TIMEOUT}" ]; do
    sleep 1
    count=$((count + 1))

    if [ "${count}" -lt 5 ]; then
        continue
    fi

    # After a brief startup period, check if Tracee is actually running
    # If no tracee processes found, it failed to start
    if ! check_tracee_running > /dev/null 2>&1; then
        if [ -f "${LOG_OUTPUT_FILE}" ]; then
            handle_tracee_error "Process terminated early (see logs above)"
        else
            die "Tracee process terminated early without creating log file"
        fi
    fi
done

info "Elapsed time: ${count} seconds"

tracee_pid=$(get_tracee_pid_from_pidfile fail)
info "Tracee PID from file: ${tracee_pid}"

cooldown=5
info "Wait ${cooldown} seconds for Tracee to finish initializing"
sleep "${cooldown}"

info "Tracee successfully started"
info "To stop Tracee, run: ./scripts/tracee_stop.sh -w ${TRACEE_WORKDIR}"
