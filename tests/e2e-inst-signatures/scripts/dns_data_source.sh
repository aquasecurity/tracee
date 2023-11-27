#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

ping -c 1 google.com > /dev/null
