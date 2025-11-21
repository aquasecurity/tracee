#!/usr/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

# set vars
prog=io_uring_writev
dir=tests/e2e-inst-signatures/scripts
# test if prog was compiled and compile if not
if [[ ! -x $dir/$prog ]]; then
    gcc $dir/$prog.c -o $dir/$prog || exit_err "could not compile $prog.c"
    chmod +x $dir/$prog
fi
# run test
./$dir/$prog || exit_err "could not run $prog"

# remove prog
rm -f $dir/$prog