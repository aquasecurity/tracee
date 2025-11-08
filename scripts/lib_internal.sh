#!/bin/sh

#
# internal library
#

__LIB_INTERNAL_NAME="lib_internal.sh"

# prevent multiple sourcing
if [ -n "${__LIB_INTERNAL_SH_SOURCED}" ]; then
    return 0
fi
__LIB_INTERNAL_SH_SOURCED=1

# must be sourced, not executed
case "${0##*/}" in
    "${__LIB_INTERNAL_NAME}")
        printf "[%s]: %s\n" "${__LIB_INTERNAL_NAME}" "This script must be sourced, not executed."
        exit 1
        ;;
esac

# Detect CI/GitHub Actions environment
# GitHub Actions sets GITHUB_ACTIONS=true and CI=true
# In CI environments, timestamps are typically already provided by the CI system
__CI_ENVIRONMENT=0
if [ "${GITHUB_ACTIONS}" = "true" ] || [ "${CI}" = "true" ]; then
    __CI_ENVIRONMENT=1
fi

# Check for timestamp override
# FORCE_LOG_TIMESTAMPS=1 forces timestamps even in CI
# FORCE_LOG_TIMESTAMPS=0 disables timestamps even in local environments
__LOG_TIMESTAMPS=1 # default: include timestamps
if [ "${__CI_ENVIRONMENT}" -eq 1 ]; then
    __LOG_TIMESTAMPS=0 # CI: disable timestamps by default
fi
# Allow override via FORCE_LOG_TIMESTAMPS
if [ -n "${FORCE_LOG_TIMESTAMPS}" ]; then
    __LOG_TIMESTAMPS="${FORCE_LOG_TIMESTAMPS}"
fi

# Set timestamp format based on the availability of the date command
#
# Format: ISO 8601 UTC timestamp with microsecond precision and 'Z' suffix
# - %Y-%m-%d      → 4-digit year, 2-digit month, 2-digit day
# - T             → Literal 'T' separator between date and time (ISO 8601)
# - %H:%M:%S      → 2-digit hour (00–23), minute, and second
# - .%6N          → Decimal point followed by microseconds (first 6 digits of nanoseconds)
# - Z             → Literal 'Z' to indicate UTC (Zulu time)
__CMD_DATE_AVAILABLE=0
if command -v date > /dev/null 2>&1; then
    __CMD_DATE_AVAILABLE=1
    __nanosecs=$(date -u '+.%6N' 2> /dev/null)
    __status=$?
    if [ ${__status} -ne 0 ] || [ -z "${__nanosecs}" ] || [ "${__nanosecs}" = "." ]; then
        __CMD_DATE_FORMAT='+%Y-%m-%dT%H:%M:%S.000000Z'
    else
        # assuming that the date command supports nanoseconds
        __CMD_DATE_FORMAT='+%Y-%m-%dT%H:%M:%S.%6NZ'
    fi
fi

__CMD_DATE_DEFAULT_VALUE="1970-01-01T00:00:00.000000Z"

############
# functions
############

# __get_timestamp returns the current timestamp in ISO 8601 UTC (Zulu time) format.
# For more see __setup_timestamp function.
#
# Usage:
#   __get_timestamp
#
# Example:
#   __get_timestamp
#
# Output:
#   2025-05-14T19:39:49.339664Z # if date command is available and microsecond precision is supported
#   2025-05-14T19:39:49.000000Z # if date command is available but does not support microsecond precision
#   1970-01-01T00:00:00.000000Z # if date command is not available or fails
__get_timestamp() {
    if [ "${__CMD_DATE_AVAILABLE}" -eq 1 ]; then
        if __get_timestamp_date_out=$(date -u "${__CMD_DATE_FORMAT}" 2> /dev/null); then
            __get_timestamp_ts="${__get_timestamp_date_out}"
        else
            __get_timestamp_ts="${__CMD_DATE_DEFAULT_VALUE}"
        fi
    else
        __get_timestamp_ts="${__CMD_DATE_DEFAULT_VALUE}"
    fi

    printf '%s' "${__get_timestamp_ts}"
}

# __log logs an library message with timestamp and level.
# Timestamps can be controlled via FORCE_LOG_TIMESTAMPS variable.
#
# $1: LEVEL - Log level (e.g., INFO, WARN, ERROR).
# $2: MESSAGE - Message to log.
#
# Usage:
#   __log LEVEL MESSAGE...
#
# Example:
#   __log "INFO" "This is an informational message."
#
# Output (with timestamps):
#   [1970-01-01T00:00:00.000000Z] [script_name] [lib.sh] [INFO] This is an informational message.
# Output (without timestamps):
#   [script_name] [lib.sh] [INFO] This is an informational message.
__log() {
    __log_level="$1"
    if [ -z "${__log_level}" ]; then
        if [ "${__LOG_TIMESTAMPS}" -eq 1 ]; then
            __log_timestamp="$(__get_timestamp)"
            printf '[%s] [%s] [%s] [ERROR] __log: No LEVEL provided\n' "${__log_timestamp}" "${__SCRIPT_NAME}" "${__LIB_NAME}" >&2
        else
            printf '[%s] [%s] [ERROR] __log: No LEVEL provided\n' "${__SCRIPT_NAME}" "${__LIB_NAME}" >&2
        fi
        return 1
    fi
    shift

    if [ "${__LOG_TIMESTAMPS}" -eq 1 ]; then
        # Include timestamp
        __log_timestamp="$(__get_timestamp)"
        printf '[%s] [%s] [%s] [%s] %s\n' "${__log_timestamp}" "${__SCRIPT_NAME}" "${__LIB_NAME}" "${__log_level}" "$*" >&2
    else
        # Omit timestamp
        printf '[%s] [%s] [%s] %s\n' "${__SCRIPT_NAME}" "${__LIB_NAME}" "${__log_level}" "$*" >&2
    fi
}

# __debug logs a debug-level message if DEBUG is set.
#
# $1: MESSAGE - Debug message to log.
#
# Usage:
#   __debug MESSAGE...
#
# Example:
#   __debug "This is a debug message."
#
# Output:
#   [1970-01-01T00:00:00.000000Z] [script_name] [lib.sh] [DEBUG] This is a debug message.
__debug() {
    if [ "${DEBUG}" -eq 0 ]; then
        return 0
    fi

    __log "DEBUG" "$@" || {
        __status=$?
        printf '[%s] [%s] [ERROR] __debug: Failed to log message\n' "${__SCRIPT_NAME}" "${__LIB_NAME}" >&2
        return ${__status}
    }
}

# __error logs an error message.
#
# $1: MESSAGE - Error message to log.
#
# Usage:
#   __error MESSAGE...
#
# Example:
#   __error "This is an error message."
#
# Output:
#   [1970-01-01T00:00:00.000000Z] [script_name] [lib.sh] [ERROR] This is an error message.
__error() {
    __log "ERROR" "$@" || {
        __status=$?
        printf '[%s] [%s] [ERROR] __error: Failed to log message\n' "${__SCRIPT_NAME}" "${__LIB_NAME}" >&2
        return ${__status}
    }
}

# __info logs an informational message.
#
# $1: MESSAGE - Informational message to log.
#
# Usage:
#   __info MESSAGE...
#
# Example:
#   __info "This is an informational message."
#
# Output:
#   [1970-01-01T00:00:00.000000Z] [script_name] [lib.sh] [INFO] This is an informational message.
__info() {
    __log "INFO" "$@" || {
        __status=$?
        printf '[%s] [%s] [ERROR] __info: Failed to log message\n' "${__SCRIPT_NAME}" "${__LIB_NAME}" >&2
        return ${__status}
    }
}

# __warn logs a warning message.
#
# $1: MESSAGE - Warning message to log.
#
# Usage:
#   __warn MESSAGE...
#
# Example:
#   __warn "This is a warning message."
#
# Output:
#   [1970-01-01T00:00:00.000000Z] [script_name] [lib.sh] [WARN] This is a warning message.
__warn() {
    __log "WARN" "$@" || {
        __status=$?
        printf '[%s] [%s] [ERROR] __warn: Failed to log message\n' "${__SCRIPT_NAME}" "${__LIB_NAME}" >&2
        return ${__status}
    }
}

# __collect_missing_cmds collects missing commands from a given list.
#
# $@: CMD1 CMD2... - List of commands to check.
#
# Usage:
#   __collect_missing_cmds CMD1 CMD2...
#
# Example:
#   __collect_missing_cmds git grep sed
#
# Output:
#   git grep sed # if any are missing
#   # empty if all commands are available
__collect_missing_cmds() {
    if [ -z "$1" ]; then
        __error "__collect_missing_cmds: No CMD provided"
        return 1
    fi

    __collect_missing_cmds_missing=""

    for cmd in "$@"; do
        if ! command -v "${cmd}" > /dev/null 2>&1; then
            __collect_missing_cmds_missing="${__collect_missing_cmds_missing} ${cmd}"
        fi
    done

    printf "%s" "${__collect_missing_cmds_missing}"
}

# __lib_require_cmds checks for required commands and exits if any are missing (error code 127).
#
# $@: CMD1 CMD2... - List of commands to check.
#
# Usage:
#   __lib_require_cmds CMD1 CMD2...
#
# Example:
#   __lib_require_cmds git grep sed
__lib_require_cmds() {
    if [ -z "$1" ]; then
        __error "__lib_require_cmds: No CMD provided"
        return 1
    fi

    __lib_require_cmds_missing="$(__collect_missing_cmds "$@")" || {
        __status=$?
        __error "__lib_require_cmds: Failed to collect missing commands"
        return ${__status}
    }

    if [ -n "${__lib_require_cmds_missing}" ]; then
        __error "The following required command(s) are missing:${__lib_require_cmds_missing}"
        __error "Please install the missing dependencies and try again."
        exit 127
    fi
}
