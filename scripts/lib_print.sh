#!/bin/sh

#
# print
#

__LIB_PRINT_NAME="lib_print.sh"

# prevent multiple sourcing
if [ -n "${__LIB_PRINT_SH_SOURCED}" ]; then
    return 0
fi
__LIB_PRINT_SH_SOURCED=1

# must be sourced, not executed
case "${0##*/}" in
    "${__LIB_PRINT_NAME}")
        printf "[%s]: %s\n" "${__LIB_PRINT_NAME}" "This script must be sourced, not executed."
        exit 1
        ;;
esac

############
# variables
############

__BLOCK_SEP_CHAR="-"
__BLOCK_SEP_SPACE=" "
__BLOCK_SEP_LINE=""
__PRINT_SCRIPT_END_TRAPPED=0

############
# functions
############

# print_script_start logs the start of a script with a decorative title.
# It also sets a trap to log a separator at script exit (EXIT).
# Subsequent calls will fail if already trapped to avoid duplicate traps.
#
# $1: TITLE - Title for the script start message.
#
# Usage:
#   print_script_start TITLE
#
# Example:
#   print_script_start "My Script Title"
#
# Output:
#   --- My Script Title ---
print_script_start() {
    print_script_start_title="$1"
    if [ -z "${print_script_start_title}" ]; then
        __error "print_script_start: No TITLE provided"
        return 1
    fi

    # POSIX-compliant trap guard
    if [ "${__PRINT_SCRIPT_END_TRAPPED}" -eq 1 ]; then
        __error "print_script_start: __print_script_end already trapped"
        return 1
    fi

    info "${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_SPACE}${print_script_start_title}${__BLOCK_SEP_SPACE}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}"

    print_script_start_sep_len=$((3 + 1 + ${#print_script_start_title} + 1 + 3))
    __BLOCK_SEP_LINE=$(printf "%${print_script_start_sep_len}s" | tr ' ' "${__BLOCK_SEP_CHAR}")

    # print at the end of the script
    trap __print_script_end EXIT
    __PRINT_SCRIPT_END_TRAPPED=1
}

# __print_script_end (internal) logs a decorative separator at the end of the script.
#
# Usage:
#   __print_script_end
__print_script_end() {
    info "${__BLOCK_SEP_LINE}" || {
        __status=$?
        __error "__print_script_end: Failed to log message"
        return ${__status}
    }
}

# set_print_block_sep sets the character used for decorative separators.
#
# $1: CHARACTER - Character to use for the separator (default: "-").
#
# Usage:
#   set_print_block_sep CHARACTER
#
# Example:
#   set_print_block_sep "#"
set_print_block_sep() {
    set_print_block_sep_chr="$1"
    if [ -n "${set_print_block_sep_chr}" ] && [ "${#set_print_block_sep_chr}" -eq 1 ]; then
        __BLOCK_SEP_CHAR="$1"
    else
        __warn "set_print_block_sep: Block separator must be a single character. Ignoring '${set_print_block_sep_chr}' and using '${__BLOCK_SEP_CHAR}'."
    fi
}
