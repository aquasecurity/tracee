#!/bin/sh

#
# testing
#

__LIB_TESTING_NAME="lib_testing.sh"

# prevent multiple sourcing
if [ -n "${__LIB_TESTING_SH_SOURCED:-}" ]; then
    return 0
fi
__LIB_TESTING_SH_SOURCED=1

# must be sourced, not executed
case "${0##*/}" in
    "${__LIB_TESTING_NAME}")
        printf "[%s]: %s\n" "${__LIB_TESTING_NAME}" "This script must be sourced, not executed."
        exit 1
        ;;
esac

############
# functions
############

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
#   [1970-01-01T00:00:00.000000Z] [script_name] [TEST] This is a test message.
test_log() {
    log "TEST" "$@" || {
        __status=$?
        __error "test_log: Failed to log message"
        return ${__status}
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
    if [ -z "${test_pass_msg}" ]; then
        __error "__test_pass: No MESSAGE provided"
        return 1
    fi

    test_log "$(printf '[PASS] %s (exit: %d)\n' "${test_pass_msg}" "${test_pass_code}")"
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
    if [ -z "${test_fail_msg}" ]; then
        __error "__test_fail: No MESSAGE provided"
        return 1
    fi

    test_log "$(printf '[FAIL] %s (exit: %d)\n' "${test_fail_msg}" "${test_fail_code}")"

    if [ -n "${__TEST_CURRENT_FN}" ]; then
        __TEST_FAILED_ASSERTS=$(printf "%s\n - %s: %s" "${__TEST_FAILED_ASSERTS}" "${__TEST_CURRENT_FN}" "${test_fail_msg}")
    else
        __TEST_FAILED_ASSERTS=$(printf "%s\n - %s" "${__TEST_FAILED_ASSERTS}" "${test_fail_msg}")
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

    if [ "${test_assert_eq_expected}" = "${test_assert_eq_actual}" ]; then
        __test_pass "${test_assert_eq_desc}" "${test_assert_eq_code}" || {
            __status=$?
            __error "test_assert_eq: Failed to pass test"
            return ${__status}
        }
    else
        __test_fail "${test_assert_eq_desc}" "${test_assert_eq_code}" && {
            __status=$?
            __error "test_assert_eq: Failed to fail test"
            return ${__status}
        }

        test_log "$(printf ' - Expected: %s, Got: %s\n' "${test_assert_eq_expected}" "${test_assert_eq_actual}")"
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

    if [ "${test_assert_neq_not_expected}" != "${test_assert_neq_actual}" ]; then
        __test_pass "${test_assert_neq_desc}" "${test_assert_neq_code}" || {
            __status=$?
            __error "test_assert_neq: Failed to pass test"
            return ${__status}
        }
    else
        __test_fail "${test_assert_neq_desc}" "${test_assert_neq_code}" && {
            __status=$?
            __error "test_assert_neq: Failed to fail test"
            return ${__status}
        }

        test_log "$(printf ' - NOT expected: %s, Got: %s\n' "${test_assert_neq_not_expected}" "${test_assert_neq_actual}")"
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
    if [ -z "${test_run_name}" ]; then
        __error "test_run: No test NAME provided"
        return 1
    fi
    shift

    if [ -z "$1" ]; then
        __error "test_run: No test FUNCTION provided"
        return 1
    fi

    __TEST_CURRENT_FN="$1"
    test_run_prev_failed_asserts="${__TEST_FAILED_ASSERTS}"

    test_log "$(printf '== %s: Running ==\n' "${test_run_name}")"

    "$@" # run TEST function with ARGS

    test_run_result=$?
    if [ "${test_run_result}" -ne 0 ] || [ "${__TEST_FAILED_ASSERTS}" != "${test_run_prev_failed_asserts}" ]; then
        __TEST_ALL_PASSED=1
        __TEST_FAILED_TESTS=$(printf "%s\n - %s (%s)\n" "${__TEST_FAILED_TESTS}" "${test_run_name}" "${__TEST_CURRENT_FN}")
    fi

    test_log "$(printf '== %s: Completed ==\n' "${test_run_name}")"
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
    if [ "${__TEST_ALL_PASSED}" -eq 0 ]; then
        __test_pass "All tests completed successfully" 0 || {
            __status=$?
            __error "test_summary: Failed to pass test"
            return ${__status}
        }
    else
        test_log "$(printf '\n\nFailed tests:\n%s\n\nFailed assertions:\n%s\n\b' "${__TEST_FAILED_TESTS}" "${__TEST_FAILED_ASSERTS}")"
        __test_fail "Some tests failed" 1 && {
            __status=$?
            __error "test_summary: Failed to fail test"
            return ${__status}
        }
    fi
}
