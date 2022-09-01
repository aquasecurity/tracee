#!/bin/sh

#
# checks tracee-ebpf and tracee-rules are healthy
#

TRACEE_EBPF_URL="http://localhost:3366/healthz"
TRACEE_RULES_URL="http://localhost:4466/healthz"

set -e

wget -qO- -S $TRACEE_EBPF_URL
wget -qO- -S $TRACEE_RULES_URL
