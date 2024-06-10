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

# Tests to exclude from running
EXCLUDE_TESTS="PROCTREE_DATA_SOURCE CONTAINERS_DATA_SOURCE WRITABLE_DATA_SOURCE DNS_DATA_SOURCE"

# Remove excluded tests from TESTS variable
for exclude_test in $EXCLUDE_TESTS; do
	TESTS=${TESTS//$exclude_test/}
done

# Remove any leading or trailing whitespace
TESTS=$(echo "$TESTS" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

backup_export "$SIG_SOURCE_DIR"
# Put all the tests files in the EXCLUDE_TESTS variable into a variable
EXCLUDED_FILES=""
for exclude_test in $EXCLUDE_TESTS; do
	signature_file=$(find_signature_file "$SIG_SOURCE_DIR" "$exclude_test")
	if [[ -n $signature_file ]]; then
		EXCLUDED_FILES+=" $(basename $signature_file)"
		remove_sig_from_export "$signature_file" "$SIG_SOURCE_DIR"
	fi
done
EXCLUDED_FILES=$(echo "$EXCLUDED_FILES" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

info "Tests to run - $TESTS"

. /etc/os-release

if [[ ! -d ./signatures ]]; then
	restore_export "$SIG_SOURCE_DIR"
    error_exit "need to be in tracee root directory"
fi

rm -rf ${TRACEE_TMP_DIR:?}/* || error_exit "could not delete $TRACEE_TMP_DIR"

KERNEL=$(uname -r)
KERNEL_MAJ=$(echo "$KERNEL" | cut -d'.' -f1)

if [[ $KERNEL_MAJ -lt 5 && "$KERNEL" != *"el8"* ]]; then
	restore_export "$SIG_SOURCE_DIR"
    info_exit "skip test in kernels < 5.0 (and not RHEL)"
fi

git config --global --add safe.directory "*"

print_environment
compile_tracee "E2E_INST_FILES_TO_EXCLUDE=\"$EXCLUDED_FILES\""

restore_export "$SIG_SOURCE_DIR"

anyerror=""

# Analyze tests

cleanup

for TEST in $TESTS; do

    info
    info "= TEST: $TEST =============================================="
    info

	if ! special_tests_setup "$TEST"; then
		continue
	fi
	
	if ! signature_file=$(find_signature_file "$SIG_SOURCE_DIR" "$TEST"); then
		error "No signature file found for $TEST - $signature_file"
		anyerror="${anyerror}$TEST,"
	fi
	events=$(extract_events_from_signature_file "$signature_file")",analyze_essentials"

	info "Events to capture - $events"

	# Run tracee to capture events
	capture_events_file="$SCRIPT_TMP_DIR/capture-events-$$"
	caputre_log_file="$SCRIPT_TMP_DIR/capture-log-$$"
	run_tracee "$events" "$capture_events_file" "$caputre_log_file" "$SIG_DIR" "--output option:disable-parse-arguments"
	
	# Wait for tracee to start
	if ! wait_for_tracee "$caputre_log_file"; then
		anyerror="${anyerror}$TEST,"
		continue
	fi

	run_test "$TEST"
	# Sleep so events can finish processing
	sleep 3
	kill_tracee
	
	if ! check_test "$TEST""_CAPTURE_EVENTS" "$caputre_log_file" ""; then
		anyerror="${anyerror}$TEST,"
		cleanup
		continue
	fi

	cp $capture_events_file /tmp/$TEST-events.json
	cp $capture_log /tmp/$TEST-logs

	info "ANALYZING EVENTS"

	# Run tracee with signatures on captured events
	analyze_events_file="$SCRIPT_TMP_DIR/analyze-events-$$"
	analyze_log_file="$SCRIPT_TMP_DIR/analyze-log-$$"
	run_tracee "$TEST" "$analyze_events_file" "$analyze_log_file" "$SIG_DIR" "--input json:$capture_events_file"

    # Sleep so events can finish processing
    # TODO: make analyze mode work with the pid file
	sleep 5
	kill_tracee

	if ! check_test "$TEST" "$caputre_log_file $analyze_log_file" "$analyze_events_file"; then
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
