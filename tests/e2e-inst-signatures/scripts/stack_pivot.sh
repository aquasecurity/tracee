#!/usr/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

prog=stack_pivot
dir=tests/e2e-inst-signatures/scripts
gcc $dir/$prog.c -pthread -o $dir/$prog || exit_err "could not compile $prog.c"
./$dir/$prog 2>&1 > /tmp/$prog.log || exit_err "could not run $prog"