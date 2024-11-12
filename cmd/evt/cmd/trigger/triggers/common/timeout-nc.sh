#!/bin/sh

# sched_process_exec      2
# security_file_open     11
# shared_object_loaded    2
# arch_prctl              2
# security_file_open     12
# sched_process_fork      1
# process_execute_failed  5
# security_socket_create  1
# security_socket_bind    1
# sched_process_exit      2

timeout 0.1 nc -l -p 8888
