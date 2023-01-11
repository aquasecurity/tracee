#!/bin/sh

do_magic_write() {
    tmpFileName=$1
    echo "AAAAA" > $tmpFileName
}

do_ls() {
    ls > /dev/null
}

do_which_ls() {
    which ls > /dev/nul
}

do_ls_uname() {
    # run on the same core to ensure event order
    taskset -c 0 ls; uname
} > /dev/null

do_docker_run() {
    outputFileName=$1
    output=$(docker run -d --rm alpine)
    $(echo $output > $outputFileName)
}

get_dockerd_pid() {
    outputFileName=$1
    output=$(pidof dockerd)
    $(echo $output > $outputFileName)
}

do_file_open() {
    cat /proc/self/comm
}

# $1 is the function to call
# $2 is the temp file to optionally output to
$1 $2
