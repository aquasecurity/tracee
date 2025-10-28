#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

if [[ ${UID} -ne 0 ]]; then
    exit_err "must be root"
fi

rmmod hijack
