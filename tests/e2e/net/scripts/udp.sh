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
    timeout --preserve-status 3 nc -u -l 8090 &
    pid=$!

    if [[ $pid -eq 0 ]]; then
        exit_err "could not start udp daemon"
    fi

}

start_daemon
ip netns exec e2ens1 bash -c "echo udpmsg01 | nc -w 1 -u 172.16.17.1 8090"
wait $pid
start_daemon
ip netns exec e2ens1 bash -c "echo udpmsg02 | nc -w 1 -u 172.16.17.1 8090"
wait $pid
start_daemon
ip netns exec e2ens1 bash -c "echo udpmsg03 | nc -w 1 -u 172.16.17.1 8090"
wait $pid