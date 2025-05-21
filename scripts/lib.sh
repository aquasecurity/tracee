#!/bin/sh

#
# lib
#

#
# Functions and variables starting with __ are internal.
# They are not intended to be used directly by the consumer of the library.
#

# prevent multiple sourcing
if [ -n "${__LIB_SH_SOURCED}" ]; then
    # once the lib is sourced, __warn is already available
    __warn "This script is already sourced."
    return 0
fi
__LIB_SH_SOURCED=1

__LIB_NAME="lib.sh"
__SCRIPT_NAME="${0##*/}" # POSIX-safe script name (no 'basename' dependency)

# must be sourced, not executed
case "${0##*/}" in
    "${__LIB_NAME}")
        printf "[%s]: %s\n" "${__LIB_NAME}" "This script must be sourced, not executed."
        exit 1
        ;;
esac

# set DEBUG level to 0 if not a number
DEBUG=$((${DEBUG:-0} + 0)) 2> /dev/null || DEBUG=0

# enable shell tracing if DEBUG is greater than 1
if [ "${DEBUG}" -gt 1 ]; then
    set -x
fi

# Require __LIB_DIR to be set to the library directory
# The caller must set this before sourcing lib.sh
if [ -z "${__LIB_DIR}" ]; then
    printf "[%s]: ERROR: __LIB_DIR must be set before sourcing lib.sh\n" "${__LIB_NAME}" >&2
    printf "[%s]: Example: __LIB_DIR=\"\${0%%/*}\" . \"\${__LIB_DIR}/lib.sh\"\n" "${__LIB_NAME}" >&2
    return 1
fi

# shellcheck disable=SC1091
. "${__LIB_DIR}/lib_internal.sh" || {
    __status=$?
    printf "[%s]: %s\n" "${__LIB_NAME}" "Failed to source lib_internal.sh"
    return ${__status}
}

# at this point, internal functions are available

# list of library files to source
__lib_files="lib_log.sh lib_print.sh lib_misc.sh lib_git.sh lib_testing.sh"

# Source each library file
for lib_file in ${__lib_files}; do
    # shellcheck disable=SC1090
    . "${__LIB_DIR}/${lib_file}" || {
        __status=$?
        __error "Failed to source ${lib_file}"
        return ${__status}
    }
done

# assuming as available built-ins: printf, test, command, shift, set, exit etc.
# NOTE: all required commands (from sparse sourced files) must be checked here
__lib_require_cmds basename date mktemp rm sed tr xargs || {
    __status=$?
    __error "Failed to check required commands"
    return ${__status}
}

__debug "Debug mode is enabled"
__debug "${__LIB_NAME} successfully loaded"
__debug "Script name: $0"
__debug "Script PID: $$"
__debug "Script arguments: $*"
