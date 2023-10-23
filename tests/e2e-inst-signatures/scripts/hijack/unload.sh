#!/bin/bash

if [[ $UID -ne 0 ]]; then
    echo must be root
    exit 1
fi

rmmod hijack
