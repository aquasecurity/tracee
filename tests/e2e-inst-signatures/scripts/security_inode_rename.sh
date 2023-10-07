#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

sleep 2
echo test >> /tmp/aaa.txt || exit_err "failed writing file"
mv /tmp/aaa.txt /tmp/bbb.txt || exit_err "failed renaming file"
