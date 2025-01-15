#!/bin/sh

# sched_process_exec    1
# security_file_open    6
# shared_object_loaded  5
# arch_prctl            1
# security_path_notify  1
# sched_process_exit    1

inotifywait -m /tmp -t 1
