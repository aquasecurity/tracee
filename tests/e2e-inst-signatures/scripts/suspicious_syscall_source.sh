#!/usr/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

prog=sys_src_tester
dir=tests/e2e-inst-signatures/scripts
gcc $dir/$prog.c -pthread -o $dir/$prog -z execstack || exit_err "could not compile $prog.c"
./$dir/$prog stack 2>&1 > /tmp/$prog.log || exit_err "could not run $prog"
./$dir/$prog heap 2>&1 > /tmp/$prog.log || exit_err "could not run $prog"
./$dir/$prog mmap 2>&1 > /tmp/$prog.log || exit_err "could not run $prog"
./$dir/$prog thread-stack 2>&1 > /tmp/$prog.log || exit_err "could not run $prog"