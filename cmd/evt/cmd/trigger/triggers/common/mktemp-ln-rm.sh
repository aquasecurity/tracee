#!/bin/sh

# common

file=$(mktemp /tmp/fileXXXXXX)
link1=$(mktemp /tmp/link1XXXXXX)

rm -f "$link1"

ln -s "$file" "$link1"
rm "$file" "$link1"
