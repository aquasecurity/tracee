#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

touch file_modification.txt

`which echo` write content >> file_modification.txt || exit_err "failed writing to file"
