#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

output_file="vfs_writev.txt"
prog=writev
dir=tests/e2e-inst-signatures/scripts/writev_tester
gcc $dir/$prog.c -o $dir/$prog -lpthread || exit_err "could not compile $prog.c"

./$dir/$prog > /dev/null

rm -f $output_file
rm -f $dir/$prog