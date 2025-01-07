#!/bin/sh

# sched_process_exec      2
# security_file_open     11
# shared_object_loaded    2
# arch_prctl              2
# security_file_open     12
# sched_process_fork      1
# process_execute_failed  5 (the amount of wrong PATH entries)
# security_socket_create  1
# security_socket_bind    1
# sched_process_exit      2

basename=$(basename "$0")
socket_path=$(mktemp -u /tmp/"$basename"_XXXXXX)
timeout 0.1 nc -l -U "$socket_path"
rm -f "$socket_path"
