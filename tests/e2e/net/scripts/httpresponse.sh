#!/bin/bash

HOST="google.com"

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

command -v curl > /dev/null || exit_err "missing curl tool"

curl $HOST
