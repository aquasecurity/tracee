#!/bin/sh

# common

# security_file_open   60
# shared_object_loaded 44
# sched_process_exec    2
# arch_prctl            2
# security_bpf_prog     4
# kallsyms_lookup_name  2
# kprobe_attach         1
# bpf_attach            1
# sched_process_exit    2

bpftrace -e 'kprobe:__do_sys_vfork { }' &
bpftrace_pid=$!
sleep 3
kill -KILL $bpftrace_pid
