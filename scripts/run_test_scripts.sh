#!/bin/sh
# Main script to run all unit test scripts in the scripts directory.

# shellcheck disable=SC1091
. "${0%/*}/lib.sh"

UNIT_TEST_SCRIPTS_DIR="scripts"
FAILED_TESTS=""

require_cmds find

UNIT_TEST_SCRIPTS_SRC=$(find "$UNIT_TEST_SCRIPTS_DIR" -type f -name '*_test.sh')

#
# script start
#

print_script_start "Running Unit Test Scripts" || die "Failed to start script"

for script in $UNIT_TEST_SCRIPTS_SRC; do
    info "Running: $script"
    echo

    sh "$script" || {
        FAILED_TESTS="$FAILED_TESTS $script"
    }

    echo
done

if [ -n "$FAILED_TESTS" ]; then
    info "Some test scripts failed:"
    for failed in $FAILED_TESTS; do
        info " - $failed"
    done
    exit 1
else
    info "All test scripts passed."
    exit 0
fi
