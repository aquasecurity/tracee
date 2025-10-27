#!/bin/bash

if [[ $UID -ne 0 ]]; then
    echo must be root
    exit 1
fi

sudo lsmod | grep -q hijack && {
    echo module already loaded
    exit 0
}

address=$(cat /proc/kallsyms | grep -E " sys_call_table$" | cut -d' ' -f1)
echo "Loading hijack module with syscall table address: 0x$address"
insmod ./hijack.ko "table=0x${address}" || {
    echo "could not load module with insmod"
    exit 1
}
