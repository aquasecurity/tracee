#!/bin/sh
# tracee_common.sh - Common functions and variables for tracee scripts

__LIB_DIR="${0%/*}"
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

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
TRACEE_WORKDIR_DEFAULT="/tmp/tracee"

# Setup common paths and variables
setup_tracee_paths() {
    # Set defaults using parameter expansion
    TRACEE_WORKDIR="${TRACEE_WORKDIR:-${TRACEE_WORKDIR_DEFAULT}}"
    TRACEE_WORKDIR=$(realpath "${TRACEE_WORKDIR}" 2> /dev/null \
        || printf "%s" "${TRACEE_WORKDIR}")

    export TRACEE_WORKDIR
}

# Default error handler - scripts can override this
handle_tracee_error() {
    error_msg="$1"
    die "${error_msg:-Tracee operation failed}"
}

# get_running_tracee_pids - Find all running tracee binary processes
#
# Returns: Prints PIDs of running tracee processes, one per line
#          Returns 0 if any found, 1 if none found
# Note: Excludes zombie processes (state Z) as they cannot be interacted with
#       Only matches exact binary names, not scripts or other processes
get_running_tracee_pids() {
    # Use pgrep with exact match (-x) for known tracee binary names
    # This avoids matching shell scripts or other processes with "tracee" in the name
    pids=""
    for bin_name in tracee tracee-e2e tracee-e2e-net; do
        # -x = exact match on process name
        found=$(pgrep -x "${bin_name}" 2> /dev/null || true)
        if [ -n "${found}" ]; then
            if [ -n "${pids}" ]; then
                pids="${pids}
${found}"
            else
                pids="${found}"
            fi
        fi
    done

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
