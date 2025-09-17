#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

# Create a test file to trigger LSM events
touch /tmp/lsm_test_file || exit_err "failed to create test file"

# Reading the file should trigger the LSM file_open hook
cat /tmp/lsm_test_file || exit_err "failed to read test file"

# Clean up
rm -f /tmp/lsm_test_file
