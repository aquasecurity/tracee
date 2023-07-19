#!/usr/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

bash -c "bash -c \"bash -c 'sleep 2; ls' & sleep 10\" & exec sleep 10" > /dev/null &
sleep 10
