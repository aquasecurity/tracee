#!/bin/sh

do_magic_write() {
    tmpFileName=$1
    echo "AAAAA" > $tmpFileName
}

do_ls() {
    ls > /dev/null
}

do_docker_run() {
    outputFileName=$1
    output=$(docker run -d --rm alpine)
    $(echo $output > $outputFileName)
}

do_file_open() {
    cat /proc/self/comm > /dev/null
}

do_ping() {
    ping -q -c 1 8.8.8.8 > /dev/null
}

# $1 is the function to call
# $2 is the temp file to optionally output to
$1 $2
