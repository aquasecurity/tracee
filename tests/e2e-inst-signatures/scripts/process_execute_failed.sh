#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

echo "echo hello > /dev/null" > test.sh
chmod +x test.sh
ls . > /dev/null # necessary for the execution path to work
# Executing the script will fail as this is not an ELF and does not start with `#!`
# This will produce the `process_execute_failed` event.
# Afterwards it will try to run it with bash
exec ./test.sh &
rm test.sh