#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

# Create test files to trigger the features fallback test
# The BPF programs hook into vfs_open operations

# Create and open a test file to trigger vfs_open
TEST_FILE="/tmp/features_fallback_test_file"

# Single file operation to trigger the BPF programs
touch "$TEST_FILE" || exit_err "failed to create and open test file"
cat "$TEST_FILE" >/dev/null 2>&1 || exit_err "failed to read test file"

# Clean up
rm -f "$TEST_FILE"