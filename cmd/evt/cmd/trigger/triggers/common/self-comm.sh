#!/bin/sh

# common

echo "fake-comm" > /proc/self/comm # trigger magic-write by fake-comm
echo "fake-comm" > /proc/self/comm # trigger do_truncate by fake-comm
