#!/bin/sh

#
# lib.sh internal
#

# enable shell tracing if DEBUG=2
[ "$DEBUG" = "2" ] && set -x

__LIB_NAME="lib.sh"
__SCRIPT_NAME="${0##*/}" # POSIX-safe script name (no 'basename' dependency)

__log() {
    level="$1"
    shift

    if command -v date >/dev/null 2>&1; then
        # use date to get the current timestamp
        timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    else
        # fallback to a static timestamp
        timestamp="1970-01-01T00:00:00Z"
    fi

    printf '[%s] [%s] [%s] [%s] %s\n' "$timestamp" "$__SCRIPT_NAME" "$__LIB_NAME" "$level" "$*" >&2
}

# commands used in this function are assumed to be available as built-ins
__collect_missing_cmds() {
    missing=""

    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing="$missing $cmd"
        fi
    done

    printf "%s" "$missing"
}

# check for required commands
__lib_require_cmds() {
    missing="$(__collect_missing_cmds "$@")"

    if [ -n "$missing" ]; then
        __log "ERROR" "The following required command(s) are missing:$missing"
        __log "ERROR" "Please install the missing dependencies and try again."
        exit 127
    fi
}

# check for lib dependencies here
# assuming as available built-in: echo, printf, test, command, set, exit
__lib_require_cmds date tr


#
# logging functions
#

log() {
    level="$1"
    shift

    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '[%s] [%s] [%s] %s\n' "$timestamp" "$__SCRIPT_NAME" "$level" "$*" >&2
}

debug() {
    case "$DEBUG" in
        ''|0) return ;;
        *[!0-9]*) return ;;  # not a number
    esac

    [ "$DEBUG" -gt 0 ] 2>/dev/null && log "DEBUG" "$@"
}


info() {
    log "INFO" "$@"
}

warn() {
    log "WARN" "$@"
}

error() {
    log "ERROR" "$@"
}


#
# exit functions
#

die() {
  msg="$1"
  code="${2:-1}"
  error "$msg"
  exit "$code"
}


#
# print functions
#

__BLOCK_SEP_CHAR="-"
__BLOCK_SEP_SPACE=" "
__BLOCK_SEP_LINE=""

print_script_start() {
    title="$1"
    log "INFO" "${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_SPACE}$title${__BLOCK_SEP_SPACE}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}${__BLOCK_SEP_CHAR}"
    
    sep_len=$((3 + 1 + ${#title} + 1 + 3))
    __BLOCK_SEP_LINE=$(printf "%${sep_len}s" | tr ' ' "$__BLOCK_SEP_CHAR")
    
    # print at the end of the script
    trap __print_script_end EXIT
}

__print_script_end() {
    log "INFO" "$__BLOCK_SEP_LINE"
}

set_print_block_sep() {
    if [ -n "$1" ] && [ "${#1}" -eq 1 ]; then
        __BLOCK_SEP_CHAR="$1"
    else
        warn "Block separator must be a single character. Ignoring '$1' and using '$__BLOCK_SEP_CHAR'."
    fi
}


#
# misc functions
#

require_cmds() {
    missing="$(__collect_missing_cmds "$@")"

    if [ -n "$missing" ]; then
        error "The following required command(s) are missing:$missing"
        die "Please install the missing dependencies and try again." 127
    fi
}

debug "Debug mode is enabled"
debug "$__LIB_NAME successfully loaded"
debug "Script name: $0"
debug "Script PID: $$"
debug "Script arguments: $*"
