#!/bin/sh
set -e
mount -t debugfs debugfs /sys/kernel/debug/
exec "$@"