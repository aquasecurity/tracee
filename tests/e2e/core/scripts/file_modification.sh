#!/bin/bash

info() {
    echo -n "INFO: "
    echo "$@"
}

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

# Use /tmp which should be on native filesystem
file_path="/tmp/file_modification.txt"

# Check if we're on a problematic filesystem
fs_type=$(df -T "$(dirname "${file_path}")" | tail -1 | awk '{print $2}')
case "${fs_type}" in
    vboxsf|9p|nfs)
        info "WARNING: Attempting to manipulate file on virtual/network filesystem (${fs_type})"
        info "file_modification events may not work properly on this filesystem type"
        info "Consider testing on native filesystem"
esac

# Create file to have initial ctime
touch "${file_path}"

# Write to file to trigger file_modification event
$(which echo) "write content" >> "${file_path}" || exit_err "failed writing to ${file_path}"
