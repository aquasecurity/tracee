#!/bin/sh

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "${SCRIPT_DIR}/tracee_common.sh"

require_cmds cat sleep

# Default values specific to stop script
TIMEOUT_DEFAULT=10
FORCE_DEFAULT=0

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    --install-path, -i PATH  Installation path for tracee (default: ${TRACEE_INSTALL_PATH_DEFAULT})
    --timeout, -t SECONDS    Timeout to wait for graceful shutdown (default: ${TIMEOUT_DEFAULT})
    --force, -f              Force immediate termination (SIGKILL)
    --help, -h               Show this help message

Examples:
    $0                                          # Stop tracee in default location
    $0 --install-path /var/tracee               # Stop tracee in custom location
    $0 --timeout 30                             # Wait up to 30 seconds for graceful shutdown
    $0 --force                                  # Immediately send KILL signal
EOF
}

# Parse command line arguments
while [ $# -gt 0 ]; do
    case $1 in
        --install-path | -i)
            # shellcheck disable=SC2034
            TRACEE_INSTALL_PATH="$2" # it is used in tracee_common.sh
            shift 2
            ;;
        --timeout | -t)
            TIMEOUT="$2"
            shift 2
            ;;
        --force | -f)
            FORCE=1
            shift
            ;;
        --help | -h)
            show_help
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            die "Usage: $0 [OPTIONS]. Use --help for more information."
            ;;
    esac
done

# Set defaults
TIMEOUT="${TIMEOUT:-${TIMEOUT_DEFAULT}}"
FORCE="${FORCE:-${FORCE_DEFAULT}}"

# Setup common paths
setup_tracee_paths

# Custom error handler for stop script
handle_tracee_error() {
    error_msg="$1"
    die "${error_msg:-Tracee does not appear to be running}"
}

stop_tracee() {
    tracee_pid="$1"

    if [ "${FORCE}" = 1 ]; then
        info "Force stopping Tracee process ${tracee_pid}"
        if kill -KILL "${tracee_pid}" 2> /dev/null; then
            info "Tracee process ${tracee_pid} terminated (SIGKILL)"
            return 0
        else
            error "Failed to send KILL signal to process ${tracee_pid}"
            return 1
        fi
    fi

    info "Gracefully stopping Tracee process ${tracee_pid}"
    if ! kill -TERM "${tracee_pid}" 2> /dev/null; then
        error "Failed to send TERM signal to process ${tracee_pid}"
        return 1
    fi

    info "Waiting up to ${TIMEOUT} seconds for graceful shutdown"
    count=0
    while [ "${count}" -lt "${TIMEOUT}" ]; do
        if ! kill -0 "${tracee_pid}" 2> /dev/null; then
            info "Tracee process ${tracee_pid} terminated gracefully"
            break
        fi
        sleep 1
        count=$((count + 1))
    done

    # Check if process is still running after timeout
    if kill -0 "${tracee_pid}" 2> /dev/null; then
        info "Process still running after ${TIMEOUT} seconds, sending KILL signal"
        if kill -KILL "${tracee_pid}" 2> /dev/null; then
            info "Tracee process ${tracee_pid} terminated (SIGKILL)"
            sleep 1
        else
            error "Failed to send KILL signal to process ${tracee_pid}"
            return 1
        fi
    fi

    return 0
}

#
# Main
#

set -e

info "Stopping Tracee"

# Check if tracee is running
tracee_pid=$(get_tracee_pid_from_pidfile fail)

if [ -z "${tracee_pid}" ]; then
    info "Tracee is not running"
    cleanup_tracee_pid_file
    exit 0
fi

info "Found Tracee running with PID ${tracee_pid}"

# Stop the process
if stop_tracee "${tracee_pid}"; then
    info "Tracee stopped successfully"
    cleanup_tracee_pid_file
else
    die "Failed to stop Tracee"
fi
