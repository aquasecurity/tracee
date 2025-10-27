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
# Try modprobe first, then fall back to insmod
modarg="./hijack.ko table=0x${address}"
if ! modprobe ${modarg} 2>/dev/null; then
    echo "modprobe failed, trying insmod..."
    insmod ${modarg} || {
        echo "could not load module with insmod"
        exit 1
    }
else
    echo "Module loaded successfully with modprobe"
fi
