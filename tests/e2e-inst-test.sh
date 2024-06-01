#!/bin/bash

#
# This test is executed by github workflows inside the action runners
#

SCRIPT_TMP_DIR=/tmp/analyze_test
TRACEE_TMP_DIR=/tmp/tracee

SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
TESTS_DIR="$SCRIPT_DIR/e2e-inst-signatures/scripts"
SIG_DIR="$SCRIPT_DIR/../dist/e2e-inst-signatures"
SIG_SOURCE_DIR="$SCRIPT_DIR/e2e-inst-signatures/"

source $SCRIPT_DIR/inst_tests_funcs.sh

if [[ $UID -ne 0 ]]; then
    error_exit "need root privileges"
fi

# Default test to run if no other is given
TESTS=${INSTTESTS:=VFS_WRITE}

# Remove any leading or trailing whitespace
TESTS=$(echo "$TESTS" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

info "Tests to run - $TESTS"

. /etc/os-release

if [[ ! -d ./signatures ]]; then
    error_exit "need to be in tracee root directory"
fi

rm -rf ${TRACEE_TMP_DIR:?}/* || error_exit "could not delete $TRACEE_TMP_DIR"

KERNEL=$(uname -r)
KERNEL_MAJ=$(echo "$KERNEL" | cut -d'.' -f1)

if [[ $KERNEL_MAJ -lt 5 && "$KERNEL" != *"el8"* ]]; then
    info_exit "skip test in kernels < 5.0 (and not RHEL)"
fi

git config --global --add safe.directory "*"

print_environment
compile_tracee "E2E_INST_FILES_TO_EXCLUDE=\"$EXCLUDED_FILES\""

anyerror=""


# Run tests, one by one

for TEST in $TESTS; do

    info
    info "= TEST: $TEST =============================================="
    info

	special_tests_setup "$TEST"
	skip_test=$?
	if [[ $skip_test -eq 1 ]]; then
		continue
	fi

	# Run tracee
	events_file="$SCRIPT_TMP_DIR/build-$$"
	log_file="$SCRIPT_TMP_DIR/tracee-log-$$"
	run_tracee "$TEST" "$events_file" "$log_file" "$SIG_DIR"
	
	# Wait for tracee to start
	if ! wait_for_tracee "$log_file"; then
		anyerror="${anyerror}$TEST,"
		continue
	fi

	run_test "$TEST"

    # Sleep so events can finish processing

    sleep 3
	kill_tracee
	if ! check_test "$TEST" "$log_file" "$events_file"; then
		anyerror="${anyerror}$TEST,"
	fi
	cleanup
done

# Print summary and exit with error if any test failed

info
if [[ $anyerror != "" ]]; then
    info "ALL TESTS: FAILED: ${anyerror::-1}"
    exit 1
fi

info "ALL TESTS: SUCCESS"

exit 0
