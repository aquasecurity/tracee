#!/bin/sh

basename=$(basename "$0")
socket_path=$(mktemp -u /tmp/"$basename"_XXXXXX)
timeout 0.1 nc -l -U "$socket_path"
rm -f "$socket_path"
