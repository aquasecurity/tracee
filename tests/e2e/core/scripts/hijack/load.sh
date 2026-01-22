#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

info() {
    echo -n "INFO: "
    echo "$@"
}

if [[ ${UID} -ne 0 ]]; then
    exit_err "must be root"
fi

sudo lsmod | grep -q hijack && {
    info "module already loaded"
    exit 0
}

address=$(cat /proc/kallsyms | grep -E " sys_call_table$" | cut -d' ' -f1)
info "loading hijack module with syscall table address: 0x${address}"
insmod ./hijack.ko "table=0x${address}" || {
    exit_err "could not load module with insmod"
}

info "hijack module loaded"
