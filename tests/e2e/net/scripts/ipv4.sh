#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

if [[ $UID != 0 ]]; then
    exit_err "need root privileges"
fi

command -v ping || exit_err "missing ping tool"

ip netns exec e2ens1 ping -W 5 -c 3 172.16.17.1
