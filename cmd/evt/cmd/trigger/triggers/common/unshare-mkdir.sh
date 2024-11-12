#!/bin/sh

# common

# sched_process_exec      2
# security_file_open     13
# shared_object_loaded    2
# arch_prctl              2
# debugfs_create_dir      1
# debugfs_create_file     2
# security_socket_create 15
# device_add              1
# switch_task_ns          1
# sched_process_fork      1
# magic_write             3
# security_sb_mount       1
# process_execute_failed  4
# sched_process_exit      2

unshare --mount --pid --net --ipc --uts --user --fork --map-root-user sh &
sleep 1 # wait for the unshare to complete and exit
exit 0
