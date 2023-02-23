#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

touch vfs_write.txt

`which echo` write content >> vfs_write.txt || exit_err "failed writing to file"
