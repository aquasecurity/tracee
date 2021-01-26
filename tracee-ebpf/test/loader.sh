#! /bin/bash

# example: `./loader.sh ls 4 5`
# will run 4 threads that continuously run `ls` in a loop for 5 seconds
# then run tracee with small buffer size to increase the chance for lost events:
# `make build && sudo ./tracee -e mmap -e close -e mprotect -e openat -e security_file_open -b 1`

set -e
command="$1"
parallalism="$2"
duration="$3"

for i in 1.."$parallalism"; do
  bash -c "while true; do $command > /dev/null; done" &
done
sleep "$duration"
kill $(jobs -p)