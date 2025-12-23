#!/bin/sh

# common

unshare --mount --pid --net --ipc --uts --user --fork --map-root-user sh &
sleep 1 # wait for the unshare to complete and exit
exit 0
