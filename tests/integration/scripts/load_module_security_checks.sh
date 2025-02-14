#!/usr/bin/bash -e

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

# Build and load module
dir="scripts/module"
cd $dir || exit_err "could not cd to $dir"
make && ./load.sh || exit_err "could not load module"

# Sleep a bit to allow module to load
sleep 5
lsmod | grep linux_module || exit_err "module not loaded"

# Unload module after 10 seconds
nohup sleep 10 > /dev/null 2>&1 && ./unload.sh &
