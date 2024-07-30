#!/bin/bash

ARCH=$(uname -m)

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

prog=chdir_tester
prog32=chdir_tester_32
dir=tests/e2e-inst-signatures/scripts

gcc $dir/$prog.c -o $dir/$prog || exit_err "could not compile $prog.c"
mkdir test_dir_64 || exit_err "failed creating dir"
ln -s test_dir_64 test_link || exit_err "failed creating link"
./$dir/$prog 2>&1 > /tmp/$prog.log || exit_err "could not run $prog"
rm test_link || exit_err "failed removing link"
rm -r test_dir_64 || exit_err "failed removing dir"

if [[ $ARCH == x86_64 ]]; then
    gcc $dir/$prog.c -m32 -o $dir/$prog32 || exit_err "could not compile $prog.c"
else
    . /etc/os-release
    case $ID in
    "ubuntu")
        arm-linux-gnueabi-gcc $dir/$prog.c -o $dir/$prog32 || exit_err "could not compile $prog.c"
    ;;
    "almalinux")
        arm-linux-gnu-gcc $dir/$prog.c -o $dir/$prog32 || exit_err "could not compile $prog.c"
    ;;
    *)
        echo "Unsupported OS: $ID"
        exit 1
    ;;
    esac
fi
mkdir test_dir_32 || exit_err "failed creating dir"
ln -s test_dir_32 test_link || exit_err "failed creating link"
./$dir/$prog32 2>&1 > /tmp/$prog32.log || exit_err "could not run $prog32"
rm test_link || exit_err "failed removing link"
rm -r test_dir_32 || exit_err "failed removing dir"