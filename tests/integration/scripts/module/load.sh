#!/bin/bash

mod="linux_module"

if [[ $UID -ne 0 ]]; then
    echo must be root
    exit 1
fi

sudo lsmod | grep -q $mod && {
    echo module already loaded
    exit 0
}


insmod $mod.ko
