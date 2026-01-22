#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

sleep_time=${E2E_INST_TEST_SLEEP:-2}
sleep "$sleep_time"

file1_path="/tmp/aaa.txt"
file2_path="/tmp/bbb.txt"
echo test >> "${file1_path}" || exit_err "failed writing file to ${file1_path}"
mv "${file1_path}" "${file2_path}" || exit_err "failed renaming file from ${file1_path} to ${file2_path}"
