#!/usr/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

# bpftrace should be installed

# Run bpftrace command
timeout 5 bpftrace -e '
tracepoint:syscalls:sys_enter_execve {
    @my_fixed_map = count();
}' || exit 0
