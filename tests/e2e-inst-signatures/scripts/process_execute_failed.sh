#!/bin/bash

exit_err() {
    echo "ERROR: $@"
    exit 1
}

TEST_SCRIPT=/tmp/test.sh

echo "echo hello > /dev/null" > "$TEST_SCRIPT"
chmod +x "$TEST_SCRIPT"
ls . > /dev/null # necessary for the execution path to work
# Executing the script will fail as this is not an ELF and does not start with `#!`
# This will produce the `process_execute_failed` event.
# Afterwards it will try to run it with bash
exec "$TEST_SCRIPT" &
sleep 2
rm "$TEST_SCRIPT"