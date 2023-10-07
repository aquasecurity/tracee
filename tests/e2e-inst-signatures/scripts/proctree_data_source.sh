#!/usr/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

prog=proctreetester
dir=tests/e2e-inst-signatures/scripts
gcc $dir/$prog.c -o $dir/$prog -lpthread || exit_err "could not compile $prog.c"
# TIMES=5 might case some missing ppids and/or lineaage issues in github runners
TIMES=3 ./$dir/$prog 2>&1 > /tmp/$prog.log || exit_err "could not run $prog"
