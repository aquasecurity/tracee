#!/bin/bash

coproc ./dist/tracee -f e=security_file_open
pid=$COPROC_PID
sleep 10
kill -9 $pid
