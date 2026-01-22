#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

# Create a uniquely named wrapper to trigger LSM events with a specific comm name
# This avoids noise from other 'cat' processes
UNIQUE_TRIGGER="/tmp/lsm_e2e_test"

# Create the trigger script
cat > "${UNIQUE_TRIGGER}" << 'TRIGGER_EOF'
#!/bin/bash
# This script will be executed with comm=lsm_e2e_test
TESTFILE="/tmp/lsm_test_file_$$"
touch "${TESTFILE}" || exit 1
cat "${TESTFILE}" || exit 1
rm -f "${TESTFILE}"
TRIGGER_EOF

chmod +x "${UNIQUE_TRIGGER}"

# Execute the trigger (this will have comm=lsm_e2e_test)
"${UNIQUE_TRIGGER}" || exit_err "failed to trigger LSM event"

# Clean up
rm -f "${UNIQUE_TRIGGER}"
