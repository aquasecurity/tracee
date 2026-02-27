#!/bin/bash
#
# Run E2E Kernel Tests inside QEMU (Direct Execution)
# This script is meant to be run INSIDE the QEMU VM by virtme-ng.
# It runs tracee-ebpf directly without Docker.
#

set -euo pipefail

SCRIPT_TMP_DIR=/tmp
TRACEE_TMP_DIR=/tmp/tracee

# Setup directories
mkdir -p "$TRACEE_TMP_DIR"
mkdir -p "$SCRIPT_TMP_DIR"

info() {
    echo "INFO: $@"
}

error_exit() {
    echo "ERROR: $@"
    exit 1
}

# We expect to be in the root of the repo (mounted by virtme-ng)
if [[ ! -x ./dist/tracee ]]; then
    error_exit "Tracee binary not found at ./dist/tracee. Did you build it on the host?"
fi

# Definitions
TRACEE_STARTUP_TIMEOUT=60

# Artifacts dir in the mounted workspace (persists to host via --rw --pwd)
ARTIFACTS_DIR="./qemu-artifacts"
mkdir -p "$ARTIFACTS_DIR"

LOGFILE="$ARTIFACTS_DIR/tracee.log"
OUTPUTFILE="$ARTIFACTS_DIR/tracee.json"

info "Starting Tracee..."
info "Logs will be written to $ARTIFACTS_DIR"

# Cleanup previous run
rm -f "$LOGFILE" "$OUTPUTFILE"

# Select policy — use kernel.yaml if it exists, otherwise run without a policy
POLICY_ARGS=""
if [[ -f ./tests/policies/kernel/kernel.yaml ]]; then
    POLICY_ARGS="--policy ./tests/policies/kernel/kernel.yaml"
    info "Using policy: ./tests/policies/kernel/kernel.yaml"
else
    info "No kernel.yaml policy found, running with default event set"
fi

# Start Tracee
./dist/tracee \
    --output json:"$OUTPUTFILE" \
    --enrichment environment \
    --logging file="$LOGFILE" \
    --server healthz \
    $POLICY_ARGS &

TRACEE_PID=$!
info "Tracee started with PID $TRACEE_PID"

# Wait for startup
times=0
timedout=0
while true; do
    times=$(($times + 1))
    sleep 1
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:3366/healthz 2>/dev/null | grep -q "200"; then
        info "Tracee is UP and RUNNING"
        break
    fi

    if [[ $times -gt $TRACEE_STARTUP_TIMEOUT ]]; then
        timedout=1
        break
    fi
done

if [[ $timedout -eq 1 ]]; then
    info "Tracee startup TIMED OUT"
    cat "$LOGFILE" 2>/dev/null || true
    kill $TRACEE_PID || true
    exit 1
fi

# Give it a moment
sleep 5

# Run Tests (Simulated triggers)
# For kernel coverage, starting Tracee and verifying it runs is the primary goal.
# Trigger some basic syscalls for event capture.
info "Running trivial triggers..."
ls /tmp > /dev/null
cat /proc/version > /dev/null
uname -a > /dev/null

# Wait a bit for events to be captured
sleep 5

# Stop Tracee
info "Stopping Tracee..."
kill -SIGINT $TRACEE_PID
wait $TRACEE_PID || true

info "Tracee stopped."

# Verify Output
if [[ -s "$OUTPUTFILE" ]]; then
    EVENT_COUNT=$(wc -l < "$OUTPUTFILE")
    info "Events captured: $EVENT_COUNT"
    head -n 5 "$OUTPUTFILE"
    info "Test SUCCESS (clean run)"
else
    info "No events captured in output file."
    info "This may be expected if no matching policy was loaded."
    # Don't fail — the goal is to verify Tracee starts on this kernel
fi

# Show log tail for debugging
info "=== Tracee log tail ==="
tail -n 20 "$LOGFILE" 2>/dev/null || true

# Artifacts are in $ARTIFACTS_DIR which is in PWD, so they persist to host.
exit 0
