#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

./tests/e2e-inst-signatures/scripts/file_modification.sh
