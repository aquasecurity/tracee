#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

./tests/e2e/core/scripts/file_modification.sh
