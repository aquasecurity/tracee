#!/usr/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

python3 tests/e2e-inst-signatures/scripts/proctree_data_source.py
