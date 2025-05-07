#!/bin/sh

#
# lib.sh internal
# Functions and variables starting with __ are internal to the library.
# They are not intended to be used directly by the user.
#

# __init initializes the library.
# It should be called exactly once at the end of the library to:
# - set up global variables,
# - verify dependencies,
# - enable debug output,
# - and prevent re-sourcing.
__init() {
    __LIB_NAME="lib.sh"
    __SCRIPT_NAME="${0##*/}" # POSIX-safe script name (no 'basename' dependency)

    # prevent multiple sourcing
    if [ -n "$__LIB_SH_INCLUDED" ]; then
        __warn "__init: This script is already sourced."
        return 0
    fi
    __LIB_SH_INCLUDED=1

    # set internal timestamp format and availability check
    __setup_timestamp

    # must be sourced, not executed
    case "${0##*/}" in
    "$__LIB_NAME")
        __error "__init: This script must be sourced, not executed."
        exit 1
        ;;
    esac

    # set DEBUG level to 0 if not a number
    DEBUG=$((${DEBUG:-0} + 0)) 2>/dev/null || DEBUG=0

    # enable shell tracing if DEBUG is greater than 1
    if [ "$DEBUG" -gt 1 ]; then
        set -x
    fi

    # assuming as available built-ins: printf, test, command, shift, set, exit etc.
    __lib_require_cmds basename date mktemp rm sed tr xargs || {
        status=$?
        __error "__init: Failed to check required commands"
        return $status
    }

    # set default values
    __BLOCK_SEP_CHAR="-"
    __BLOCK_SEP_SPACE=" "
    __BLOCK_SEP_LINE=""
    __PRINT_SCRIPT_END_TRAPPED=0
}

# __setup_timestamp initializes the timestamp format and availability check.
#
# Format: ISO 8601 UTC timestamp with microsecond precision and 'Z' suffix
# - %Y-%m-%d      → 4-digit year, 2-digit month, 2-digit day
# - T             → Literal 'T' separator between date and time (ISO 8601)
# - %H:%M:%S      → 2-digit hour (00–23), minute, and second
# - .%6N          → Decimal point followed by microseconds (first 6 digits of nanoseconds)
# - Z             → Literal 'Z' to indicate UTC (Zulu time)
__setup_timestamp() {
    if command -v date >/dev/null 2>&1; then
        __CMD_DATE_AVAILABLE=1
    else
        __CMD_DATE_AVAILABLE=0
    fi

    if [ "$__CMD_DATE_AVAILABLE" -eq 1 ]; then
        if date -u '+%6N' >/dev/null 2>&1; then
            __CMD_DATE_FORMAT="+%Y-%m-%dT%H:%M:%S.%6NZ"
        else
            __CMD_DATE_FORMAT="+%Y-%m-%dT%H:%M:%S.000000Z"
        fi
    fi
    __CMD_DATE_DEFAULT_VALUE="1970-01-01T00:00:00.000000Z"
}

# __log (internal) logs an library message with timestamp and level.
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
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [lib.sh] [INFO] This is an informational message.
__log() {
    __log_timestamp="$(get_timestamp)"

    __log_level="$1"
    if [ -z "$__log_level" ]; then
        printf '[%s] [%s] [%s] [ERROR] __log: No LEVEL provided\n' "$__log_timestamp" "$__SCRIPT_NAME" "$__LIB_NAME" >&2
        return 1
    fi
    shift

    printf '[%s] [%s] [%s] [%s] %s\n' "$__log_timestamp" "$__SCRIPT_NAME" "$__LIB_NAME" "$__log_level" "$*" >&2
}

# __debug (internal) logs a debug-level message if DEBUG is set.
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
#   [1970-01-01T00:00:00Z] [script_name] [lib.sh] [DEBUG] This is a debug message.
__debug() {
    if [ "$DEBUG" -eq 0 ]; then
        return 0
    fi

    __log "DEBUG" "$@" || {
        status=$?
        printf '[%s] [%s] [ERROR] __debug: Failed to log message\n' "$__SCRIPT_NAME" "$__LIB_NAME" >&2
        return $status
    }
}

# __error (internal) logs an error message.
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
#   [1970-01-01T00:00:00Z] [script_name] [lib.sh] [ERROR] This is an error message.
__error() {
    __log "ERROR" "$@" || {
        status=$?
        printf '[%s] [%s] [ERROR] __error: Failed to log message\n' "$__SCRIPT_NAME" "$__LIB_NAME" >&2
        return $status
    }
}

# __info (internal) logs an informational message.
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
#   [1970-01-01T00:00:00Z] [script_name] [lib.sh] [INFO] This is an informational message.
__info() {
    __log "INFO" "$@" || {
        status=$?
        printf '[%s] [%s] [ERROR] __info: Failed to log message\n' "$__SCRIPT_NAME" "$__LIB_NAME" >&2
        return $status
    }
}

# __warn (internal) logs a warning message.
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
#   [1970-01-01T00:00:00Z] [script_name] [lib.sh] [WARN] This is a warning message.
__warn() {
    __log "WARN" "$@" || {
        status=$?
        printf '[%s] [%s] [ERROR] __warn: Failed to log message\n' "$__SCRIPT_NAME" "$__LIB_NAME" >&2
        return $status
    }
}

# __collect_missing_cmds (internal) collects missing commands from a given list.
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
        if ! command -v "$cmd" >/dev/null 2>&1; then
            __collect_missing_cmds_missing="$__collect_missing_cmds_missing $cmd"
        fi
    done

    printf "%s" "$__collect_missing_cmds_missing"
}

# __lib_require_cmds (internal) checks for required commands and exits if any are missing (error code 127).
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
        status=$?
        __error "__lib_require_cmds: Failed to collect missing commands"
        return $status
    }

    if [ -n "$__lib_require_cmds_missing" ]; then
        __error "The following required command(s) are missing:$__lib_require_cmds_missing"
        __error "Please install the missing dependencies and try again."
        exit 127
    fi
}

#
# logging functions
#

# get_timestamp returns the current timestamp in ISO 8601 UTC (Zulu time) format.
# For more see __setup_timestamp function.
#
# Usage:
#   get_timestamp
#
# Example:
#   get_timestamp
#
# Output:
#   2025-05-14T19:39:49.339664Z # if date command is available and microsecond precision is supported
#   2025-05-14T19:39:49.000000Z # if date command is available but does not support microsecond precision
#   1970-01-01T00:00:00.000000Z # if date command is not available or fails
get_timestamp() {
    if [ "$__CMD_DATE_AVAILABLE" -eq 1 ]; then
        if __ts=$(date -u "$__CMD_DATE_FORMAT" 2>/dev/null); then
            get_timestamp_ts="$__ts"
        else
            get_timestamp_ts="$__CMD_DATE_DEFAULT_VALUE"
        fi
    else
        get_timestamp_ts="$__CMD_DATE_DEFAULT_VALUE"
    fi

    printf '%s' "$get_timestamp_ts"
}

# log logs a script message with timestamp and level.
#
# $1: LEVEL - Log level (e.g., INFO, WARN, ERROR).
# $2: MESSAGE - Message to log.
#
# Usage:
#   log LEVEL MESSAGE...
#
# Example:
#   log "INFO" "This is an informational message."
#
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [INFO] This is an informational message.
log() {
    log_level="$1"
    if [ -z "$log_level" ]; then
        __error "log: No LEVEL provided"
        return 1
    fi
    shift

    printf '[%s] [%s] [%s] %s\n' "$(get_timestamp)" "$__SCRIPT_NAME" "$log_level" "$*" >&2
}

# debug logs a debug-level message if DEBUG is set.
#
# $1: MESSAGE - Debug message to log.
#
# Usage:
#   debug MESSAGE...
#
# Example:
#   debug "This is a debug message."
#
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [DEBUG] This is a debug message.
debug() {
    if [ "$DEBUG" -eq 0 ]; then
        return 0
    fi

    log "DEBUG" "$@" || {
        status=$?
        __error "debug: Failed to log message"
        return $status
    }
}

# info logs an informational message.
#
# $1: MESSAGE - Informational message to log.
#
# Usage:
#   info MESSAGE...
#
# Example:
#   info "This is an informational message."
#
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [INFO] This is an informational message.
info() {
    log "INFO" "$@" || {
        status=$?
        __error "info: Failed to log message"
        return $status
    }
}

# warn logs a warning message.
#
# $1: MESSAGE - Warning message to log.
#
# Usage:
#  warn MESSAGE...
#
# Example:
#   warn "This is a warning message."
#
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [WARN] This is a warning message.
warn() {
    log "WARN" "$@" || {
        status=$?
        __error "warn: Failed to log message"
        return $status
    }
}

# error logs an error message.
#
# $1: MESSAGE - Error message to log.
#
# Usage:
#  error MESSAGE...
#
# Example:
#   error "This is an error message."
#
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [ERROR] This is an error message.
error() {
    log "ERROR" "$@" || {
        status=$?
        __error "error: Failed to log message"
        return $status
    }
}

#
# exit functions
#

# die logs an error message and exits with a given code (default: 1).
#
# $1: MESSAGE - Error message to log.
# $2: CODE - Exit code (default: 1).
#
# Usage:
#   die MESSAGE [CODE]
#
# Example:
#   die "This is a fatal error." 127
#
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [ERROR] This is a fatal error.
#   Exits with code 127.
die() {
    die_msg="$1"
    die_code="${2:-1}"
    if [ -z "$die_msg" ]; then
        __error "die: No MESSAGE provided"
        return 1
    fi

    error "$die_msg"
    exit "$die_code"
}

#
# print functions
#

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
    if [ -z "$print_script_start_title" ]; then
        __error "print_script_start: No TITLE provided"
        return 1
    fi

    # POSIX-compliant trap guard
    if [ "$__PRINT_SCRIPT_END_TRAPPED" -eq 1 ]; then
        __error "print_script_start: __print_script_end already trapped"
        return 1
    fi

    info "${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_SPACE}$print_script_start_title${__BLOCK_SEP_SPACE}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}"

    print_script_start_sep_len=$((3 + 1 + ${#print_script_start_title} + 1 + 3))
    __BLOCK_SEP_LINE=$(printf "%${print_script_start_sep_len}s" | tr ' ' "$__BLOCK_SEP_CHAR")

    # print at the end of the script
    trap __print_script_end EXIT
    __PRINT_SCRIPT_END_TRAPPED=1
}

# __print_script_end (internal) logs a decorative separator at the end of the script.
#
# Usage:
#   __print_script_end
__print_script_end() {
    info "$__BLOCK_SEP_LINE" || {
        status=$?
        __error "__print_script_end: Failed to log message"
        return $status
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
    if [ -n "$set_print_block_sep_chr" ] && [ "${#set_print_block_sep_chr}" -eq 1 ]; then
        __BLOCK_SEP_CHAR="$1"
    else
        __warn "set_print_block_sep: Block separator must be a single character. Ignoring '$set_print_block_sep_chr' and using '$__BLOCK_SEP_CHAR'."
    fi
}

#
# git
#

# git_changed_files lists filenames changed between two refs matching the given pattern.
#
# $1: REF1 - Base git reference for comparison.
# $2: REF2 - Target git reference for comparison.
# $3: PATTERN - File pattern to filter git diff results.
#
# Usage:
#   git_changed_files REF1 REF2 PATTERN
#
# Example:
#   git_changed_files HEAD~2 HEAD 'path/*.md'
#
# Output:
#   path/file1.md
#   path/file2.md
git_changed_files() {
    git_changed_files_ref1="$1"
    git_changed_files_ref2="$2"
    git_changed_files_pattern="$3"
    if [ -z "$git_changed_files_ref1" ]; then
        __error "git_changed_files: No REF1 provided"
        return 1
    fi
    if [ -z "$git_changed_files_ref2" ]; then
        __error "git_changed_files: No REF2 provided"
        return 1
    fi
    if [ -z "$git_changed_files_pattern" ]; then
        __error "git_changed_files: No PATTERN provided"
        return 1
    fi

    # step 1: get changed files
    git_changed_files_step1=$(git diff --name-only "$git_changed_files_ref1..$git_changed_files_ref2" -- "$git_changed_files_pattern") || {
        status=$?
        __error "git_changed_files: git diff failed"
        return $status
    }

    # step 2: sanitize to lines
    git_changed_files_result=$(printf "%s\n" "$git_changed_files_step1" | xargs -n1) || {
        status=$?
        __error "git_changed_files: xargs sanitize failed"
        return $status
    }

    printf "%s\n" "$git_changed_files_result"
}

#
# misc functions
#

# require_cmds checks for required commands and exits if any are missing (error code 127).
#
# $@: CMD1 CMD2... - List of commands to check.
#
# Usage:
#   require_cmds CMD1 CMD2...
#
# Example:
#   require_cmds git grep sed
require_cmds() {
    if [ -z "$1" ]; then
        __error "require_cmds: No CMD provided"
        return 1
    fi

    require_cmds_missing="$(__collect_missing_cmds "$@")" || {
        status=$?
        __error "require_cmds: Failed to collect missing commands"
        return $status
    }

    if [ -n "$require_cmds_missing" ]; then
        error "The following required command(s) are missing:$require_cmds_missing"
        die "Please install the missing dependencies and try again." 127 || {
            status=$?
            __error "require_cmds: Failed to die"
            return $status
        }
    fi
}

# basename_strip_ext extracts basenames from filenames by removing the given extension.
#
# $1: FILES - List of filenames.
# $2: EXTENSION - File extension to remove.
#
# Usage:
#   basename_strip_ext FILES EXTENSION
#
# Example:
#   basename_strip_ext "path/file1.txt path/file2.txt" ".txt"
#
# Output:
#   file1
#   file2
basename_strip_ext() {
    basename_strip_ext_files=$(sanitize_to_lines "$1")
    basename_strip_ext_ext="$2"
    basename_strip_ext_ext="${basename_strip_ext_ext#.}" # remove leading dot if present
    if [ -z "$basename_strip_ext_files" ]; then
        __error "basename_strip_ext: No FILES provided"
        return 1
    fi
    if [ -z "$basename_strip_ext_ext" ]; then
        __error "basename_strip_ext: No EXTENSION provided"
        return 1
    fi

    # step 1: extract basenames
    basename_strip_ext_step1=$(printf "%s\n" "$basename_strip_ext_files" | xargs -n1 basename) || {
        status=$?
        __error "basename_strip_ext: xargs extract basename failed"
        return $status
    }

    # step 2: remove extension
    basename_strip_ext_result=$(printf "%s\n" "$basename_strip_ext_step1" | sed "s/\.$basename_strip_ext_ext\$//") || {
        status=$?
        __error "basename_strip_ext: sed remove extension failed"
        return $status
    }

    printf "%s\n" "$basename_strip_ext_result"
}

# sanitize_to_lines converts a delimited string to a cleaned list of lines.
# Steps:
#   - Interprets input as printf %b (so \n becomes newline),
#   - Splits by the specified delimiter (default: space),
#   - Trims whitespace and removes empty lines.
#
# $1: INPUT - Input string to sanitize.
# $2: DELIMITER - Delimiter to split the input string (default: space).
#
# Usage:
#   sanitize_to_lines INPUT [DELIMITER]
#
# Example1:
#   sanitize_to_lines "apple banana cherry date"
#   sanitize_to_lines "apple,banana, cherry , date" ","
#   sanitize_to_lines "apple\nbanana\ncherry\ndate"
#
# Output1:
#   apple
#   banana
#   cherry
#   date
sanitize_to_lines() {
    sanitize_to_lines_input=$1
    sanitize_to_lines_delimiter=$2
    if [ -z "$sanitize_to_lines_input" ]; then
        # do not error if no input is provided
        return 0
    fi
    if [ -z "$sanitize_to_lines_delimiter" ]; then
        sanitize_to_lines_delimiter=" "
    fi

    # step 1: convert input into lines
    sanitize_to_lines_step1=$(printf "%b" "$sanitize_to_lines_input" | tr "$sanitize_to_lines_delimiter" '\n') || {
        status=$?
        __error "sanitize_to_lines: tr failed"
        return $status
    }

    # step 2: trim leading/trailing whitespace
    sanitize_to_lines_step2=$(printf "%s\n" "$sanitize_to_lines_step1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//') || {
        status=$?
        __error "sanitize_to_lines: sed trim failed"
        return $status
    }

    # step 3: remove empty lines
    sanitize_to_lines_result=$(printf "%s\n" "$sanitize_to_lines_step2" | sed '/^$/d') || {
        status=$?
        __error "sanitize_to_lines: sed remove empty lines failed"
        return $status
    }

    # output result
    printf "%s\n" "$sanitize_to_lines_result"
}

# list_diff computes the symmetric difference between two lists.
# That is, it prints items that are only in A or only in B.
#
# $1: LIST_A - First list of items (space, comma, or newline separated).
# $2: LIST_B - Second list of items (space, comma, or newline separated).
#
# Usage:
#   list_diff LIST_A LIST_B
#
# Example:
#   list_diff "a\nb\nc" "b\nc\nd"
#   list_diff "a b c" "b c d"
#   list_diff "a,b,c" "b,c,d"
#
# Output:
#   a
#   d
list_diff() {
    list_diff_list_a="$1"
    list_diff_list_b="$2"

    list_diff_list_a_step1=$(sanitize_to_lines "$list_diff_list_a") || {
        status=$?
        __error "list_diff: sanitize_to_lines LIST_A failed"
        return $status
    }
    list_diff_list_b_step1=$(sanitize_to_lines "$list_diff_list_b") || {
        status=$?
        __error "list_diff: sanitize_to_lines LIST_B failed"
        return $status
    }
    list_diff_sanitized_a=$(printf "%s\n" "$list_diff_list_a_step1" | sort -u) # sort assumed not to fail
    list_diff_sanitized_b=$(printf "%s\n" "$list_diff_list_b_step1" | sort -u) # sort assumed not to fail

    # a not in b
    while IFS= read -r a; do
        match_found=0
        while IFS= read -r b; do
            if [ "$a" = "$b" ]; then
                match_found=1
                break
            fi
        done <<EOF
$list_diff_sanitized_b
EOF

        # if no match found, print the item
        if [ "$match_found" -eq 0 ]; then
            printf '%s\n' "$a"
        fi
    done <<EOF
$list_diff_sanitized_a
EOF
    : # guard set -e on empty input

    # b not in a
    while IFS= read -r b; do
        match_found=0
        while IFS= read -r a; do
            if [ "$b" = "$a" ]; then
                match_found=1
                break
            fi
        done <<EOF
$list_diff_sanitized_a
EOF

        # if no match found, print the item
        if [ "$match_found" -eq 0 ]; then
            printf '%s\n' "$b"
        fi
    done <<EOF
$list_diff_sanitized_b
EOF
    : # guard set -e on empty input
}

# next_available_fd finds the next available file descriptor (FD) number.
# It scans the /proc/self/fd directory to find the highest used FD and returns the next available one.
#
# Usage:
#   next_available_fd
#
# Example:
#   echo $(next_available_fd)
#
# Output:
#   3 # if 2 is the highest used FD
next_available_fd() {
    max_fd=2

    for fd_path in /proc/self/fd/*; do
        fd=${fd_path##*/}

        # ensure $fd is a valid integer
        case $fd in
        '' | *[!0-9]*) continue ;;
        esac

        if [ "$fd" -gt "$max_fd" ]; then
            max_fd=$fd
        fi
    done

    printf '%s\n' "$((max_fd + 1))"
}

# capture_outputs captures the outputs of a command (stdout, stderr and return value) into variables.
# It uses temporary files to store the outputs and ensures that the files are cleaned up afterwards.
# The captured outputs are then assigned to the original variables.
#
# $1: STDOUT_VAR - Variable name for capturing stdout.
# $2: STDERR_VAR - Variable name for capturing stderr.
# $3: RET_VAL_VAR - Variable name for capturing the return value.
# $4: COMMAND... - Command to execute and capture outputs from.
#
# Usage:
#   capture_outputs STDOUT_VAR STDERR_VAR RET_VAL_VAR COMMAND...
#
# Example:
#   capture_outputs my_stdout_var my_stderr_var my_ret_val_var ls -l
#
# Output:
#   my_stdout_var: Captured stdout from the command.
#   my_stderr_var: Captured stderr from the command.
#   my_ret_val_var: Captured return value from the command.
capture_outputs() {
    capture_outputs_out_var=$1
    capture_outputs_err_var=$2
    capture_outputs_ret_val_var=$3
    shift 3

    if [ -z "$capture_outputs_out_var" ]; then
        __error "capture_outputs: No STDOUT_VAR provided"
        return 1
    fi
    if [ -z "$capture_outputs_err_var" ]; then
        __error "capture_outputs: No STDERR_VAR provided"
        return 1
    fi
    if [ -z "$capture_outputs_ret_val_var" ]; then
        __error "capture_outputs: No RET_VAL_VAR provided"
        return 1
    fi

    capture_outputs_tmp_out=$(mktemp) || {
        __error "capture_outputs: Failed to create tmp file for stdout"
        return 1
    }
    capture_outputs_tmp_err=$(mktemp) || {
        __error "capture_outputs: Failed to create tmp file for stderr"
        rm -f "$capture_outputs_tmp_out"
        return 1
    }

    capture_outputs_ret_val_tmp=0
    # shellcheck disable=SC2034 # used indirectly
    "$@" >"$capture_outputs_tmp_out" 2>"$capture_outputs_tmp_err" || capture_outputs_ret_val_tmp=$?
    # "$@" >"$capture_outputs_tmp_out" 2>"$capture_outputs_tmp_err"

    # shellcheck disable=SC2034 # used indirectly
    capture_outputs_out_var_tmp=$(cat "$capture_outputs_tmp_out") || {
        __error "capture_outputs: Failed to read stdout from tmp file"
        rm -f "$capture_outputs_tmp_out" "$capture_outputs_tmp_err"
        return 1
    }
    # shellcheck disable=SC2034 # used indirectly
    capture_outputs_err_var_tmp=$(cat "$capture_outputs_tmp_err") || {
        __error "capture_outputs: Failed to read stderr from tmp file"
        rm -f "$capture_outputs_tmp_out" "$capture_outputs_tmp_err"
        return 1
    }

    rm -f "$capture_outputs_tmp_out" "$capture_outputs_tmp_err" || {
        __error "capture_outputs: Failed to remove tmp files"
        return 1
    }

    eval "$capture_outputs_out_var=\"\$capture_outputs_out_var_tmp\"" || {
        __error "capture_outputs: Failed to assign stdout to $capture_outputs_out_var"
        return 1
    }
    eval "$capture_outputs_err_var=\"\$capture_outputs_err_var_tmp\"" || {
        __error "capture_outputs: Failed to assign stderr to $capture_outputs_err_var"
        return 1
    }
    eval "$capture_outputs_ret_val_var=\$capture_outputs_ret_val_tmp" || {
        __error "capture_outputs: Failed to assign return value to $capture_outputs_ret_val_var"
        return 1
    }

    return 0
}

#
# test functions
#

# test_init initializes the test environment.
# It resets the test status variables and prepares for running tests.
test_init() {
    __TEST_ALL_PASSED=0
    __TEST_FAILED_TESTS=""
    __TEST_FAILED_ASSERTS=""
}

# test_log logs a test message with a specific format.
#
# $1: MESSAGE - Message to log.
#
# Usage:
#   test_log MESSAGE...
#
# Example:
#   test_log "This is a test message."
#
# Output:
#   [1970-01-01T00:00:00Z] [script_name] [TEST] This is a test message.
test_log() {
    log "TEST" "$@" || {
        status=$?
        __error "__pass: Failed to log message"
        return $status
    }
}

# __test_pass (internal) logs a successful test result.
#
# $1: MESSAGE - Message describing the test result.
# $2: CODE - Status code to output in the test result (default: 0).
#
# Usage:
#   __test_pass MESSAGE [CODE]
#
# Example:
#   __test_pass "Test passed" 1
#   __test_pass "Test passed"
#
# Output:
#   [PASS] Test passed (exit: 1)
#   [PASS] Test passed (exit: 0)
__test_pass() {
    test_pass_msg="$1"
    test_pass_code="${2:-0}" # default to 0
    if [ -z "$test_pass_msg" ]; then
        __error "__test_pass: No MESSAGE provided"
        return 1
    fi

    test_log "$(printf '[PASS] %s (exit: %d)\n' "$test_pass_msg" "$test_pass_code")"
}

# __test_fail (internal) logs a failed test result.
#
# $1: MESSAGE - Message describing the failure.
# $2: CODE - Status code to output in the test result (default: 1).
#
# Usage:
#   __test_fail MESSAGE [CODE]
#
# Example:
#   __test_fail "Test failed" 1
#   __test_fail "Test failed"
#
# Output:
#   [FAIL] Test failed (exit: 1)
#   [FAIL] Test failed (exit: 0)
__test_fail() {
    test_fail_msg="$1"
    test_fail_code="${2:-1}" # default to 1
    if [ -z "$test_fail_msg" ]; then
        __error "__test_fail: No MESSAGE provided"
        return 1
    fi

    test_log "$(printf '[FAIL] %s (exit: %d)\n' "$test_fail_msg" "$test_fail_code")"

    if [ -n "$__TEST_CURRENT_FN" ]; then
        __TEST_FAILED_ASSERTS=$(printf "%s\n - %s: %s" "$__TEST_FAILED_ASSERTS" "$__TEST_CURRENT_FN" "$test_fail_msg")
    else
        __TEST_FAILED_ASSERTS=$(printf "%s\n - %s" "$__TEST_FAILED_ASSERTS" "$test_fail_msg")
    fi

    return 1
}

# test_assert_eq asserts that two values are equal.
#
# $1: EXPECTED - Expected value.
# $2: ACTUAL - Actual value to compare against EXPECTED.
# $3: DESCRIPTION - Description of the test.
# $4: CODE - Status code to output in the test result (default: 0).
#
# Usage:
#   test_assert_eq EXPECTED ACTUAL DESCRIPTION [CODE]
#
# Example:
#   test_assert_eq "value1" "value1" "Test description"
#   test_assert_eq "value1" "value2" "Test description" 1
#
# Output:
#   [PASS] Test description (exit: 0)
#   [FAIL] Test description (exit: 1)
test_assert_eq() {
    test_assert_eq_expected="$1"
    test_assert_eq_actual="$2"
    test_assert_eq_desc="$3"
    test_assert_eq_code="${4:-0}" # default to 0

    if [ "$test_assert_eq_expected" = "$test_assert_eq_actual" ]; then
        __test_pass "$test_assert_eq_desc" "$test_assert_eq_code" || {
            status=$?
            __error "test_assert_eq: Failed to pass test"
            return $status
        }
    else
        __test_fail "$test_assert_eq_desc" "$test_assert_eq_code" && {
            status=$?
            __error "test_assert_eq: Failed to fail test"
            return $status
        }

        test_log "$(printf ' - Expected: %s, Got: %s\n' "$test_assert_eq_expected" "$test_assert_eq_actual")"
    fi
}

# test_assert_neq asserts that two values are not equal.
#
# $1: NOT_EXPECTED - Value that should NOT be equal to ACTUAL.
# $2: ACTUAL - Actual value to compare against NOT_EXPECTED.
# $3: DESCRIPTION - Description of the test.
# $4: CODE - Status code to output in the test result (default: 0).
#
# Usage:
#   test_assert_neq NOT_EXPECTED ACTUAL DESCRIPTION [CODE]
#
# Example:
#   test_assert_neq "value1" "value2" "Test description"
#   test_assert_neq "value1" "value1" "Test description" 1
#
# Output:
#   [PASS] Test description (exit: 0)
#   [FAIL] Test description (exit: 1)
test_assert_neq() {
    test_assert_neq_not_expected="$1"
    test_assert_neq_actual="$2"
    test_assert_neq_desc="$3"
    test_assert_neq_code="${4:-0}"

    if [ "$test_assert_neq_not_expected" != "$test_assert_neq_actual" ]; then
        __test_pass "$test_assert_neq_desc" "$test_assert_neq_code" || {
            status=$?
            __error "test_assert_neq: Failed to pass test"
            return $status
        }
    else
        __test_fail "$test_assert_neq_desc" "$test_assert_neq_code" && {
            status=$?
            __error "test_assert_neq: Failed to fail test"
            return $status
        }

        test_log "$(printf ' - NOT expected: %s, Got: %s\n' "$test_assert_neq_not_expected" "$test_assert_neq_actual")"
    fi
}

# test_run runs a test function and logs the result.
#
# $1: NAME - Name of the test.
# $2: FUNCTION - Function to run.
# $3: ARGS - Arguments to pass to the function (if any).
#
# Usage:
#   test_run NAME FUNCTION [ARGS...]
#
# Example:
#   test_run "Test 1" my_test_function arg1 arg2
#   test_run "Test 2" my_test_function
#
# Output:
#   == Test 1: Running ==
#   [PASS] Some assertion from Test 1 (exit: 0)
#   == Test 1: Completed ==
#
#   == Test 2: Running ==
#   [FAIL] Some assertion from Test 2 (exit: 1)
#   == Test 2: Completed ==
test_run() {
    test_run_name="$1"
    if [ -z "$test_run_name" ]; then
        __error "test_run: No test NAME provided"
        return 1
    fi
    shift

    if [ -z "$1" ]; then
        __error "test_run: No test FUNCTION provided"
        return 1
    fi

    __TEST_CURRENT_FN="$1"
    test_run_prev_failed_asserts="$__TEST_FAILED_ASSERTS"

    test_log "$(printf '== %s: Running ==\n' "$test_run_name")"

    "$@" # run TEST function with ARGS

    test_run_result=$?
    if [ "$test_run_result" -ne 0 ] || [ "$__TEST_FAILED_ASSERTS" != "$test_run_prev_failed_asserts" ]; then
        __TEST_ALL_PASSED=1
        __TEST_FAILED_TESTS=$(printf "%s\n - %s (%s)\n" "$__TEST_FAILED_TESTS" "$test_run_name" "$__TEST_CURRENT_FN")
    fi

    test_log "$(printf '== %s: Completed ==\n' "$test_run_name")"
    test_log

    __TEST_CURRENT_FN=""
}

# test_summary prints a summary of test results and exits appropriately.
#
# Usage:
#   test_summary
#
# Example:
#   test_summary
#
# Output:
#   [PASS] All tests completed successfully (exit: 0)
test_summary() {
    if [ "$__TEST_ALL_PASSED" -eq 0 ]; then
        __test_pass "All tests completed successfully" 0 || {
            status=$?
            __error "test_summary: Failed to pass test"
            return $status
        }
    else
        test_log "$(printf '\n\nFailed tests:\n%s\n\nFailed assertions:\n%s\n\b' "$__TEST_FAILED_TESTS" "$__TEST_FAILED_ASSERTS")"
        __test_fail "Some tests failed" 1 && {
            status=$?
            __error "test_summary: Failed to fail test"
            return $status
        }
    fi
}

#
# lib startup
#

__init

__debug "Debug mode is enabled"
__debug "$__LIB_NAME successfully loaded"
__debug "Script name: $0"
__debug "Script PID: $$"
__debug "Script arguments: $*"
