#!/usr/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

# Install bpftrace
apt update -y || exit_err "Failed to update package list"
apt install -y bpftrace || exit_err "Failed to install bpftrace"

# Run bpftrace command
timeout 5 bpftrace -e '
tracepoint:syscalls:sys_enter_execve {
    @my_fixed_map = count();
}' || exit 0
