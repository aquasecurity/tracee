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
command -v nc || exit_err "missing nc tool"

start_daemon() {
    nc -k -l 8090 &
    pid=$!
    
    if [[ $pid -eq 0 ]]; then
        exit_err "could not start tcp daemon"
    fi
}

start_daemon

ip netns exec e2ens1 bash -c "echo tcp01 | nc -w 1 172.16.17.1 8090"
ip netns exec e2ens1 bash -c "echo tcp02 | nc -w 1 172.16.17.1 8090"
ip netns exec e2ens1 bash -c "echo tcp03 | nc -w 1 172.16.17.1 8090"

kill $pid
