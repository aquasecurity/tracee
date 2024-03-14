#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

mkdir test_dir || exit_err "failed creating dir"
ln -s test_dir test_link || exit_err "failed creating link"
cd test_link || exit_err "failed changing directory"
cd .. || exit_err "failed changing directory back"
rm test_link || exit_err "failed removing link"
rm -r test_dir || exit_err "failed removing dir"