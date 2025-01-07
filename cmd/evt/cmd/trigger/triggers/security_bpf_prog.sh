#!/bin/sh

# security_bpf_prog

# sched_process_exec   1
# arch_prctl           2
# security_bpf_prog  487
# security_file_open   3
# sched_process_exit   1

bpftool prog dump xlated name trace_execute_finished
