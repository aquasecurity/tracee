#!/bin/bash

if [[ $UID -ne 0 ]]; then
    echo must be root
    exit 1
fi

sudo lsmod | grep -q hooker && {
    echo module already loaded
    exit 0
}

insmod ./hooker.ko "commit_creds"
