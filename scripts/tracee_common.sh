#!/bin/sh
# tracee_common.sh - Common functions and variables for tracee scripts

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "${SCRIPT_DIR}/lib.sh"

# prevent multiple sourcing
if [ -n "${__TRACEE_COMMON_INCLUDED}" ]; then
    warn "This script is already sourced."
    return 0
fi
__TRACEE_COMMON_INCLUDED=1

__LIB_NAME="tracee_common.sh"
# must be sourced, not executed
case "${0##*/}" in
    "${__LIB_NAME}")
        die "This script must be sourced, not executed."
        ;;
esac

require_cmds cat pgrep realpath

# Common default values
TRACEE_INSTALL_PATH_DEFAULT="/tmp/tracee"

# Setup common paths and variables
setup_tracee_paths() {
    # Set defaults using parameter expansion
    TRACEE_INSTALL_PATH="${TRACEE_INSTALL_PATH:-${TRACEE_INSTALL_PATH_DEFAULT}}"
    TRACEE_INSTALL_PATH=$(realpath "${TRACEE_INSTALL_PATH}" 2> /dev/null \
        || printf "%s" "${TRACEE_INSTALL_PATH}")

    TRACEE_PIDFILE="${TRACEE_INSTALL_PATH}/tracee.pid"

    export TRACEE_INSTALL_PATH TRACEE_PIDFILE
}

# Default error handler - scripts can override this
handle_tracee_error() {
    error_msg="$1"
    die "${error_msg:-Tracee operation failed}"
}

# get_tracee_pid_from_pidfile [must_fail]
#
# Attempts to read and validate the tracee PID from the PID file.
#
# Parameters:
#   must_fail - Controls error handling behavior:
#     "nofail"   - Silent mode: return 0 on any error, no output, no script exit
#     <anything> - Strict mode: log errors and call error handler on any error
#
# Return behavior:
#   Success: Prints the PID to stdout and returns 0
#   Error in "nofail" mode: Returns 0 silently
#   Error in strict mode: Calls handle_tracee_error() and exits script
#
# Validation checks performed:
#   - PID file exists
#   - PID file is readable
#   - PID file contains non-empty content
#   - Process with that PID is actually running
get_tracee_pid_from_pidfile() {
    must_fail="${1:-fail}"

    if [ ! -f "${TRACEE_PIDFILE}" ]; then
        if [ "${must_fail}" = "nofail" ]; then
            return 0
        fi

        error "Tracee PID file ${TRACEE_PIDFILE} not found"
        handle_tracee_error "PID file not found"
    fi

    if ! get_tracee_pid_from_pidfile_pid=$(cat "${TRACEE_PIDFILE}" 2> /dev/null); then
        if [ "${must_fail}" = "nofail" ]; then
            return 0
        fi

        error "Failed to read Tracee PID from ${TRACEE_PIDFILE}"
        handle_tracee_error "Cannot read PID file"
    fi

    if [ -z "${get_tracee_pid_from_pidfile_pid}" ]; then
        if [ "${must_fail}" = "nofail" ]; then
            return 0
        fi

        error "Tracee PID file ${TRACEE_PIDFILE} is empty"
        handle_tracee_error "Invalid PID file"
    fi

    if ! kill -0 "${get_tracee_pid_from_pidfile_pid}" 2> /dev/null; then
        if [ "${must_fail}" = "nofail" ]; then
            return 0
        fi

        error "Tracee process with PID ${get_tracee_pid_from_pidfile_pid} not found"
        handle_tracee_error "Tracee process is not running"
    fi

    printf "%s" "${get_tracee_pid_from_pidfile_pid}"
}

# cleanup_tracee_pid_file - Remove the PID file
cleanup_tracee_pid_file() {
    if [ -f "${TRACEE_PIDFILE}" ]; then
        info "Removing PID file ${TRACEE_PIDFILE}"
        rm -f "${TRACEE_PIDFILE}" || {
            error "Failed to remove PID file ${TRACEE_PIDFILE}"
            return 1
        }
    fi

    return 0
}

# get_running_tracee_pids - Find all running processes named "tracee"
#
# Returns: Prints PIDs of running tracee processes, one per line
#          Returns 0 if any found, 1 if none found
get_running_tracee_pids() {
    # Use ps with awk for better POSIX portability
    pids=$(ps -eo pid,comm 2> /dev/null | awk '$2 == "tracee" {print $1}')
    if [ -n "${pids}" ]; then
        printf "%s\n" "${pids}"
        return 0
    else
        return 1
    fi
}

# check_tracee_running - Check if tracee is running
#
# Returns: 0 if tracee is running, 1 if not running
# Output: Prints PID if running, nothing if not running
check_tracee_running() {
    get_running_tracee_pids 2> /dev/null || return 1
}
