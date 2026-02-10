#!/bin/sh

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "${SCRIPT_DIR}/tracee_common.sh"

require_cmds cat sleep

# Default values specific to stop script
# Note: Tracee internally waits up to 30s for pipeline drain, so we give it
# enough time to complete graceful shutdown before falling back to SIGKILL
TIMEOUT_DEFAULT=35
FORCE_DEFAULT=0

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    --workdir, -w PATH       Directory for script-managed files (used to identify tracee instance) (default: ${TRACEE_WORKDIR_DEFAULT})
    --timeout, -t SECONDS    Timeout to wait for graceful shutdown (default: ${TIMEOUT_DEFAULT})
    --force, -f              Force immediate termination (SIGKILL)
    --help, -h               Show this help message

Examples:
    $0                                          # Stop tracee in default location
    $0 --workdir /var/tracee                    # Stop tracee using custom workdir
    $0 --timeout 30                             # Wait up to 30 seconds for graceful shutdown
    $0 --force                                  # Immediately send KILL signal
EOF
}

# Parse command line arguments
while [ $# -gt 0 ]; do
    case $1 in
        --workdir | -w)
            # shellcheck disable=SC2034
            TRACEE_WORKDIR="$2" # it is used in tracee_common.sh
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
            if ! wait_for_process_exit "${tracee_pid}" 5; then
                warn "Process ${tracee_pid} did not fully exit within timeout"
            fi
        else
            die "Failed to send KILL signal to process ${tracee_pid}"
        fi
    else
        info "Gracefully stopping Tracee process ${tracee_pid}"
        if ! kill -TERM "${tracee_pid}" 2> /dev/null; then
            die "Failed to send TERM signal to process ${tracee_pid}"
        fi

        info "Waiting up to ${TIMEOUT} seconds for graceful shutdown"
        count=0
        graceful_exit=0
        while [ "${count}" -lt "${TIMEOUT}" ]; do
            # Check if process is completely gone (not zombie)
            if ! is_process_alive "${tracee_pid}"; then
                info "Tracee process ${tracee_pid} terminated gracefully"
                graceful_exit=1
                break
            fi
            sleep 1
            count=$((count + 1))
        done

        # Only send KILL if process didn't exit gracefully (avoid PID reuse race)
        if [ "${graceful_exit}" = 0 ] && is_process_alive "${tracee_pid}"; then
            info "Process still running after ${TIMEOUT} seconds, sending KILL signal"
            if kill -KILL "${tracee_pid}" 2> /dev/null; then
                info "Tracee process ${tracee_pid} terminated (SIGKILL)"
                if ! wait_for_process_exit "${tracee_pid}" 5; then
                    warn "Process ${tracee_pid} did not fully exit within timeout"
                fi
            else
                die "Failed to send KILL signal to process ${tracee_pid}"
            fi
        fi
    fi

    # Final check for zombie state (applies to both force and graceful modes)
    if is_process_zombie "${tracee_pid}"; then
        warn "Process ${tracee_pid} is in zombie state"
        warn "This indicates Tracee didn't clean up properly before exit"
        warn "The zombie will be reaped when its parent process exits"
        # Zombie is not blocking anything, just a process table entry
    fi

    return 0
}

# Check if a process is truly alive (running, not zombie)
is_process_alive() {
    pid="$1"
    # Process exists and is NOT in zombie state
    if [ -d "/proc/${pid}" ]; then
        state=$(cat "/proc/${pid}/stat" 2> /dev/null | awk '{print $3}')
        if [ "${state}" != "Z" ]; then
            return 0 # alive
        fi
    fi
    return 1 # not alive (doesn't exist or is zombie)
}

# Check if a process is in zombie state
is_process_zombie() {
    pid="$1"
    if [ -d "/proc/${pid}" ]; then
        state=$(cat "/proc/${pid}/stat" 2> /dev/null | awk '{print $3}')
        if [ "${state}" = "Z" ]; then
            return 0 # is zombie
        fi
    fi
    return 1 # not zombie
}

# Wait for process to fully exit (including zombie reaping)
wait_for_process_exit() {
    pid="$1"
    timeout="${2:-10}"

    count=0
    while [ "${count}" -lt "${timeout}" ]; do
        if [ ! -d "/proc/${pid}" ]; then
            return 0 # fully gone
        fi
        sleep 1
        count=$((count + 1))
    done

    return 1 # still exists (likely zombie)
}

#
# Main
#

set -e

info "Stopping Tracee"

# Check if tracee is running using pgrep
running_pids=$(get_running_tracee_pids 2> /dev/null || echo "")

if [ -z "${running_pids}" ]; then
    info "Tracee is not running"
    exit 0
fi

info "Found Tracee running with PID(s): ${running_pids}"

# Stop each tracee process
for tracee_pid in ${running_pids}; do
    info "Stopping PID ${tracee_pid}"
    if stop_tracee "${tracee_pid}"; then
        info "Tracee PID ${tracee_pid} stopped successfully"
    else
        die "Failed to stop Tracee PID ${tracee_pid}"
    fi
done

info "All Tracee processes stopped"
