#!/usr/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

# inotify-tools should be installed

# Create the file
touch /tmp/inotify_file

# Run inotifywait for 5 seconds only
timeout 5 inotifywait -m /tmp/inotify_file || exit 0
