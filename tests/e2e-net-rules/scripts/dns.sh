#!/bin/bash

HOST="uol.com.br"

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

command -v nslookup > /dev/null || exit_err "missing nslookup tool"

# start dns test

test() {
    sleep 1
    nslookup -type=mx $HOST
    nslookup -type=ns $HOST
    nslookup -type=soa $HOST
    nslookup -type=txt $HOST
}

test
test
test

# signature should be triggered by now
