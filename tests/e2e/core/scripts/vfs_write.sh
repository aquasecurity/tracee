#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

file_path="vfs_write.txt"
touch "${file_path}"

$(which echo) "write content" >> "${file_path}" || exit_err "failed writing to ${file_path}"

rm -f "${file_path}" # clean up
