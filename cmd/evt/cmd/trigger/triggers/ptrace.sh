#!/bin/sh

# ptrace

# sched_process_exec    2
# security_file_open   14
# shared_object_loaded  6
# arch_prctl            2
# sched_process_fork    2
# ptrace              287
# sched_process_exit    4

strace /bin/true # full path to avoid shell built-in
