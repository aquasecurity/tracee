#!/usr/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

prog=rename_and_exec
dir=tests/e2e/core/scripts

# Compile the helper program
gcc $dir/$prog.c -o $dir/$prog || exit_err "could not compile $prog.c"

# Run the rename_and_exec program with test-specific name
# This renames the process to "e2e_rename_test" and then execs /usr/bin/true
./$dir/$prog "e2e_rename_test" "/usr/bin/true" || exit_err "could not run $prog"

