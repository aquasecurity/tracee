#!/usr/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

# set vars
prog=io_uring_writev
dir=tests/e2e-inst-signatures/scripts
# compile prog
# no compilation needed as it was done in io_issue_sqe.sh
# run test
./$dir/$prog || exit_err "could not run $prog"
