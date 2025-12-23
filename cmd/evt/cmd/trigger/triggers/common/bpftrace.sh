#!/bin/sh

# common

bpftrace -e 'kprobe:__do_sys_vfork { }' &
bpftrace_pid=$!
sleep 3
kill -KILL $bpftrace_pid
