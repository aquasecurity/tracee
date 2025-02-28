#!/usr/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

# Install inotify-tools
apt update -y || exit_err "Failed to update package list"
apt install -y inotify-tools || exit_err "Failed to install inotify-tools"

# Create the file
touch /tmp/inotify_file

# Run inotifywait for 5 seconds only
timeout 5 inotifywait -m /tmp/inotify_file || exit 0
