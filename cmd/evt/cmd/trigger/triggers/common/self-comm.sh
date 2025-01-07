#!/bin/sh

# common

# magic_write        2
# security_file_open 1
# do_truncate        1
# sched_process_exit 1

echo "fake-comm" > /proc/self/comm # trigger magic-write by fake-comm
echo "fake-comm" > /proc/self/comm # trigger do_truncate by fake-comm
