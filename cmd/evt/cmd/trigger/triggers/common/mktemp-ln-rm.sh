#!/bin/sh

# common

# sched_process_exec      5
# security_file_open     17
# shared_object_loaded    5
# arch_prctl              5
# security_inode_unlink   3
# security_inode_symlink  1
# sched_process_exit      5

file=$(mktemp /tmp/fileXXXXXX)
link1=$(mktemp /tmp/link1XXXXXX)

rm -f "$link1"

ln -s "$file" "$link1"
rm "$file" "$link1"
