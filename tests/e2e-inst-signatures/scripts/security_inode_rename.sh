#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

echo test >> /tmp/aaa.txt

mv /tmp/aaa.txt /tmp/bb.txt || exit_err "failed renaming file"
