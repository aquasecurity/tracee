#!/bin/bash

HOST="google.com"
SERVER="8.8.8.8"

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

command -v nslookup > /dev/null || exit_err "missing nslookup tool"

# start dns test

test() {
    nslookup -type=mx $HOST $SERVER
    nslookup -type=ns $HOST $SERVER
    nslookup -type=soa $HOST $SERVER
    sleep 1
}

test
test
test

# signature should be triggered by now
