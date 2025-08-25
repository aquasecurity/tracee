#!/bin/bash

mod="linux_module"

if [[ $UID -ne 0 ]]; then
    echo must be root
    exit 1
fi

rmmod $mod
