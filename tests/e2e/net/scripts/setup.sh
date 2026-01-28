#!/bin/bash -ex

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

## cleanup

ip netns delete e2ens1 || true
ip link delete e2ens1-outside || true

## namespaces

ip netns add e2ens1
ip link add e2ens1-inside type veth peer name e2ens1-outside
ip link set e2ens1-outside up
ip link set e2ens1-inside netns e2ens1
sleep 1

## addresses

# outside
ip addr add 172.16.17.1/24 dev e2ens1-outside
ip addr add fd6e:a63d:071f:02f4:0000:0000:0000:0001/64 dev e2ens1-outside
ip link set dev e2ens1-outside up
sleep 1

# 2nd time (sometimes IP was not set in some kernels)
ip addr add 172.16.17.1/24 dev e2ens1-outside || true
ip addr add fd6e:a63d:071f:02f4:0000:0000:0000:0001/64 dev e2ens1-outside || true
ip link set dev e2ens1-outside up
sleep 1

# inside
ip netns exec e2ens1 ip addr add 172.16.17.2/24 dev e2ens1-inside
ip netns exec e2ens1 ip addr add fd6e:a63d:071f:02f4:0000:0000:0000:0002/64 dev e2ens1-inside
ip netns exec e2ens1 ip link set dev lo up
ip netns exec e2ens1 ip link set dev e2ens1-inside up
sleep 1

## test

ip netns exec e2ens1 ping -W 2 -c 3 fd6e:a63d:071f:02f4:0000:0000:0000:0002
ip netns exec e2ens1 ping -W 2 -c 3 172.16.17.1

exit 0
