#!/bin/bash

#
# common.sh - Common library for E2E tests
#
# This file provides shared functions for E2E tests.
# This file should be sourced, not executed directly.
#

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "ERROR: This script must be sourced, not executed directly."
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi

# Source the main library for logging and utilities
__LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../scripts" && pwd)"
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# ==============================================================================
# Test Configuration Helpers
# ==============================================================================

# Add a test configuration entry to the map
# Usage: add_test_config <config_map_name> <test_name> <policy_name> <timeout> <sleep>
# Arguments:
#   config_map_name - Name of associative array variable
#   test_name - Test identifier (e.g., "VFS_WRITE")
#   policy_name - Policy name for the test
#   timeout - Test timeout in seconds
#   sleep - Internal sleep duration in seconds
add_test_config() {
    local -n config_map="$1"
    local test_name="$2"
    local policy_name="$3"
    local timeout="$4"
    local sleep="$5"

    config_map["$test_name"]="${policy_name}:${timeout}:${sleep}"
}

# Extract policy name from test configuration map
# Usage: get_policy_name <config_map_name> <test_name>
# Arguments:
#   config_map_name - Name of associative array variable (not the value)
#   test_name - Test name key to lookup
# Map format: "policy:timeout:sleep"
get_policy_name() {
    # shellcheck disable=SC2178  # nameref to associative array is intentional
    local -n config_map="$1"
    local test_name="$2"
    local policy_name

    if [[ -z "${config_map[$test_name]:-}" ]]; then
        error "Test '${test_name}' is not configured in TEST_CONFIG_MAP"
        return 1
    fi

    policy_name=$(echo "${config_map[$test_name]}" | cut -d: -f1)
    echo "${policy_name}"
}

# Extract timeout from test configuration map
# Usage: get_test_timeout <config_map_name> <test_name>
get_test_timeout() {
    # shellcheck disable=SC2178  # nameref to associative array is intentional
    local -n config_map="$1"
    local test_name="$2"
    local timeout

    if [[ -z "${config_map[$test_name]:-}" ]]; then
        error "Test '${test_name}' is not configured in TEST_CONFIG_MAP"
        return 1
    fi

    timeout=$(echo "${config_map[$test_name]}" | cut -d: -f2)
    echo "${timeout}"
}

# Extract sleep duration from test configuration map
# Usage: get_test_sleep <config_map_name> <test_name>
get_test_sleep() {
    # shellcheck disable=SC2178  # nameref to associative array is intentional
    local -n config_map="$1"
    local test_name="$2"
    local sleep_time

    if [[ -z "${config_map[$test_name]:-}" ]]; then
        error "Test '${test_name}' is not configured in TEST_CONFIG_MAP"
        return 1
    fi

    sleep_time=$(echo "${config_map[$test_name]}" | cut -d: -f3)
    echo "${sleep_time}"
}

# ==============================================================================
# Output Formatting Functions (using lib.sh print functions)
# ==============================================================================

# Print test separator (used to separate individual tests within a section)
# Usage: print_test_separator
print_test_separator() {
    print_separator '-' 80
    info
}

# Print major section banner with top and bottom borders
# Usage: print_major_section <section_name>
print_major_section() {
    local section_name="$1"
    print_section_banner "${section_name}" "=" 80
    info
}

# Print test header with formatting
# Usage: print_test_header <test_name> [action]
print_test_header() {
    local test_name="$1"
    local action="${2:-}"
    local header_text

    if [[ -z "$action" ]]; then
        # main section headers - use banner for major sections
        print_major_section "${test_name}"
    else
        # individual test headers
        header_text="${action} TEST: ${test_name}"
        print_section_header "${header_text}" "=" 80
        info
    fi
}

# ==============================================================================
# Log Analysis Functions
# ==============================================================================

# Filter and show only WARN, ERROR, FATAL log levels
# Usage: filter_critical_logs <logfile>
filter_critical_logs() {
    local logfile="$1"
    if [[ -f "${logfile}" ]]; then
        grep -E "(WARN|ERROR|FATAL)" "${logfile}" || echo "No WARN, ERROR, or FATAL logs found"
    else
        error "Log file not found: ${logfile}"
    fi
}

# ==============================================================================
# Event Analysis Functions (JQ Helpers)
# ==============================================================================

# Get count of events matching a specific event name and policy
# Usage: get_event_match_count <outputfile> <event_name> <policy_name>
# Returns: Integer count of matching events
get_event_match_count() {
    local outputfile="$1"
    local event_name="$2"
    local policy_name="$3"

    jq -s \
        --arg event "${event_name}" \
        --arg policy "${policy_name}" \
        '
        [.[] | 
         select(.name == $event and (.policies.matched[]? == $policy))
        ] | length
        ' \
        "${outputfile}"
}

# Get events that matched multiple policies
# Usage: get_multi_policy_matches <outputfile> <event_name> <policy_name>
# Returns: Formatted string with timestamp, event, and policies
get_multi_policy_matches() {
    local outputfile="$1"
    local event_name="$2"
    local policy_name="$3"

    jq -s \
        --arg event "${event_name}" \
        --arg policy "${policy_name}" \
        -r \
        '
        [.[] | 
         select(.name == $event and
                (.policies.matched[]? == $policy) and
                (.policies.matched | length > 1))
        ] |
        .[] | "  Timestamp: \(.timestamp) | Event: \(.name) | Policies: \(.policies.matched | join(", "))"
        ' \
        "${outputfile}"
}

# Check and report multi-policy matches
# Usage: check_multi_policy_matches <outputfile> <event_name> <policy_name>
check_multi_policy_matches() {
    local outputfile="$1"
    local event_name="$2"
    local policy_name="$3"

    local multi_policy_output
    multi_policy_output=$(get_multi_policy_matches "${outputfile}" "${event_name}" "${policy_name}")

    if [[ -n "${multi_policy_output}" ]]; then
        local multi_policy_count
        multi_policy_count=$(echo "${multi_policy_output}" | wc -l)
        info "Found ${multi_policy_count} events that matched multiple policies:"
        while IFS= read -r line; do
            info "${line}"
        done <<< "${multi_policy_output}"
    fi
}

# ==============================================================================
# Test Artifact Management
# ==============================================================================

# Cleanup or preserve test artifact files based on flag
# Usage: cleanup_test_artifact_files <keep_artifacts> <file1> [file2] [file3] ...
# Arguments:
#   keep_artifacts - 0 to delete files, 1 to preserve
#   files - One or more file paths to cleanup/preserve
cleanup_test_artifact_files() {
    local keep_artifacts="$1"
    shift
    local files=("$@")

    if [[ ${keep_artifacts} -eq 1 ]]; then
        info "Test artifacts preserved:"
    fi

    for file in "${files[@]}"; do
        if [[ ${keep_artifacts} -eq 0 ]]; then
            rm -f "${file}"
        elif [[ -f "${file}" ]]; then
            info "  ${file}"
        fi
    done
}

# ==============================================================================
# Test Execution Helpers
# ==============================================================================

# Execute a test script in background with timeout
# This is a generic helper used by both core and extended test implementations
# Arguments:
#   $1 - Test name (for output file naming)
#   $2 - Name of pid_map array (nameref to store PID)
#   $3 - Timeout in seconds
#   $4 - Sleep time in seconds
#   $5 - Test script path (e.g., "${TESTS_DIR}/vfs_write.sh")
#   $6 - Test arguments (optional, e.g., "--run")
# Environment:
#   E2E_INST_TEST_SLEEP - Set to sleep_time, consumed by test scripts
run_test_background() {
    local test_name="$1"
    local -n pid_map_ref="$2"
    local timeout="$3"
    local sleep_time="$4"
    local test_script="$5"
    local test_args="${6:-}"

    # Create unique output file for this test
    local test_output_file="/tmp/test_${test_name,,}_$$"

    # Run test in background with timeout
    (
        # shellcheck disable=SC2086
        E2E_INST_TEST_SLEEP="${sleep_time}" \
            timeout --preserve-status "${timeout}" \
            "${test_script}" ${test_args}
    ) > "${test_output_file}" 2>&1 &

    # Store PID for later waiting
    # shellcheck disable=SC2034  # pid_map_ref is a nameref to caller's array, SC2034 doesn't understand nameref array assignments
    pid_map_ref["${test_name}"]=$!
}
