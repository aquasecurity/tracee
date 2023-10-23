#!/usr/bin/bash -e

KERNEL_VERSION=$(uname -r)

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

. /etc/os-release

# Build and load module
dir="tests/e2e-inst-signatures/scripts/hijack"
cd $dir || exit_err "could not cd to $dir"
make && ./load.sh || exit_err "could not load module"

# Sleep a bit to allow module to load
sleep 5
lsmod | grep hijack || exit_err "module not loaded"

# Unload module after 30 seconds
nohup sleep 30 > /dev/null 2>&1 && ./unload.sh &
