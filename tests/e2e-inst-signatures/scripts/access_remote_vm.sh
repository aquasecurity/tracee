#!/bin/bash

info_exit() {
    echo -n "INFO: "
    echo $@
    exit 0
}

info() {
    echo -n "INFO: "
    echo "$@"
}

error_exit() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

# Get the stack address from /proc/self/maps
stack_address="0x"$(grep 'stack' /proc/$$/maps | awk '{split($1, range, "-"); print range[1]}')

if [ -z "$stack_address" ]; then
  error_exit "Failed to find the stack address in /proc/self/maps"
fi

info "Stack address: $stack_address"

# Read from /proc/self/mem in given address
read_mem_file() {
  tail /proc/$$/mem -c +$1 > /dev/null
}

# Call the function to read from the stack
read_mem_file $((stack_address))
