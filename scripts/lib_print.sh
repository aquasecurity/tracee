#!/bin/sh

#
# print
#

__LIB_PRINT_NAME="lib_print.sh"

# prevent multiple sourcing
if [ -n "${__LIB_PRINT_SH_SOURCED:-}" ]; then
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
__PRINT_DEFAULT_WIDTH=80

############
# functions
############

# print_chars generates a string of repeated characters.
#
# $1: CHAR - Character to repeat.
# $2: COUNT - Number of times to repeat.
#
# Usage:
#   print_chars CHAR COUNT
#
# Example:
#   print_chars "=" 10
#
# Output:
#   ==========
print_chars() {
    print_chars_char="$1"
    print_chars_count="$2"
    if [ -z "${print_chars_char}" ]; then
        __error "print_chars: No CHAR provided"
        return 1
    fi
    if [ -z "${print_chars_count}" ]; then
        __error "print_chars: No COUNT provided"
        return 1
    fi

    printf "%${print_chars_count}s" | tr ' ' "${print_chars_char}"
}

# print_separator prints a full-width separator line.
#
# $1: CHAR - Character to use for separator (default: from __BLOCK_SEP_CHAR).
# $2: WIDTH - Width of separator (default: from __PRINT_DEFAULT_WIDTH).
#
# Usage:
#   print_separator [CHAR] [WIDTH]
#
# Example:
#   print_separator
#   print_separator "=" 100
#
# Output:
#   --------------------------------------------------------------------------------
print_separator() {
    print_separator_char="${1:-${__BLOCK_SEP_CHAR}}"
    print_separator_width="${2:-${__PRINT_DEFAULT_WIDTH}}"

    print_separator_line=$(print_chars "${print_separator_char}" "${print_separator_width}")
    info "${print_separator_line}"
}

# print_section_header prints a formatted section header with right-padding.
#
# $1: TITLE - Header title text.
# $2: CHAR - Character to use for padding (default: "=").
# $3: WIDTH - Total width of header (default: from __PRINT_DEFAULT_WIDTH).
#
# Usage:
#   print_section_header TITLE [CHAR] [WIDTH]
#
# Example:
#   print_section_header "Test Suite"
#   print_section_header "My Section" "-" 60
#
# Output:
#   = Test Suite ====================================================================
print_section_header() {
    print_section_header_title="$1"
    print_section_header_char="${2:-=}"
    print_section_header_width="${3:-${__PRINT_DEFAULT_WIDTH}}"

    if [ -z "${print_section_header_title}" ]; then
        __error "print_section_header: No TITLE provided"
        return 1
    fi

    # Format: "= TITLE "
    print_section_header_prefix="= ${print_section_header_title} "
    print_section_header_text_length=${#print_section_header_prefix}
    print_section_header_chars_needed=$((print_section_header_width - print_section_header_text_length))

    # Generate padding characters
    if [ "${print_section_header_chars_needed}" -gt 0 ]; then
        print_section_header_padding=$(print_chars "${print_section_header_char}" "${print_section_header_chars_needed}")
        info "${print_section_header_prefix}${print_section_header_padding}"
    else
        # If title is too long, just print it as-is
        info "${print_section_header_prefix}"
    fi
}

# print_section_banner prints a formatted section banner with top and bottom borders.
#
# $1: TITLE - Section title text.
# $2: CHAR - Character to use for borders (default: "=").
# $3: WIDTH - Total width of borders (default: from __PRINT_DEFAULT_WIDTH).
#
# Usage:
#   print_section_banner TITLE [CHAR] [WIDTH]
#
# Example:
#   print_section_banner "Test Suite"
#   print_section_banner "My Section" "-" 60
#
# Output:
#   ================================================================================
#   Test Suite
#   ================================================================================
print_section_banner() {
    print_section_banner_title="$1"
    print_section_banner_char="${2:-=}"
    print_section_banner_width="${3:-${__PRINT_DEFAULT_WIDTH}}"

    if [ -z "${print_section_banner_title}" ]; then
        __error "print_section_banner: No TITLE provided"
        return 1
    fi

    # Generate the border line
    print_section_banner_border=$(print_chars "${print_section_banner_char}" "${print_section_banner_width}")

    # Print top border, title, and bottom border
    info "${print_section_banner_border}"
    info "${print_section_banner_title}"
    info "${print_section_banner_border}"
}

# print_cmd runs a command, captures its output, and prints each line via info.
# This ensures all output is consistently formatted with the log prefix.
#
# $@: COMMAND - Command and arguments to execute.
#
# Usage:
#   print_cmd COMMAND [ARGS...]
#
# Example:
#   print_cmd uname -a
#   print_cmd free -h
#   print_cmd cat /etc/os-release
#
# Returns: the command's exit code.
print_cmd() {
    print_cmd_output=""
    print_cmd_rc=0
    print_cmd_output=$("$@" 2>&1) || print_cmd_rc=$?
    if [ -n "${print_cmd_output}" ]; then
        printf '%s\n' "${print_cmd_output}" | while IFS= read -r print_cmd_line; do
            info "${print_cmd_line}"
        done
    fi
    return ${print_cmd_rc}
}
