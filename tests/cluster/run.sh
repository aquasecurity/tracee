#!/usr/bin/env bash
#
# run.sh - HOST orchestrator for the Tracee k8s cluster test. Brings up the Vagrant "test" VM (QEMU, defined
# in the repo Vagrantfile), then runs tests/cluster/incluster.sh inside it: single-node k3s + build/load the
# local images + Helm deploy + apply a Policy CRD + verify Tracee traces per the policy.
#
# Usage:
#   tests/cluster/run.sh                 # full local-build cluster test in a fresh test VM
#   USE_RELEASED=1 tests/cluster/run.sh  # deploy the released aquasec/tracee image (deploy mechanics only)
#   KEEP=1 tests/cluster/run.sh          # leave the deployment up for inspection
#   DESTROY=1 tests/cluster/run.sh       # vagrant destroy the test VM when done
#   REUSE=1 tests/cluster/run.sh         # skip 'vagrant up' if the VM is already running
#
# Prereqs on the host: vagrant + the QEMU provider (same as `make vagrant`-style dev). The test VM must carry
# the build toolchain (docker + clang/llvm/libbpf) for the local image build; if it doesn't, use USE_RELEASED=1.
#
set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
VM_TYPE=test
VM_NAME=tracee-test-vm
VM_REPO=/vagrant   # Vagrantfile synced_folder "." -> /vagrant
INCLUSTER=${VM_REPO}/tests/cluster/incluster.sh

KEEP=${KEEP:-0}
DESTROY=${DESTROY:-0}
REUSE=${REUSE:-0}

log()  { printf '\n\033[1;35m### %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m### FAIL: %s\033[0m\n' "$*" >&2; exit 1; }

command -v vagrant >/dev/null 2>&1 || die "vagrant not installed"
[ -f "${REPO_DIR}/Vagrantfile" ] || die "Vagrantfile not found at repo root"
cd "${REPO_DIR}"

# Knobs forwarded into the VM (only the ones that are set), so `incluster.sh` sees them under sudo -E.
FWD=()
for v in USE_RELEASED NAMESPACE TRACEE_IMAGE POLICY_FILE READY_TIMEOUT KEEP; do
    [ -n "${!v:-}" ] && FWD+=("${v}=${!v}")
done

up() {
    if [ "${REUSE}" = "1" ] && VM_TYPE=${VM_TYPE} vagrant status "${VM_NAME}" 2>/dev/null | grep -q running; then
        log "reusing running VM ${VM_NAME}"
        return
    fi
    log "bringing up test VM (${VM_NAME}) - this provisions the kernel/build env, can take a while"
    VM_TYPE=${VM_TYPE} vagrant up "${VM_NAME}" || die "vagrant up"
}

run_incluster() {
    log "running cluster test inside the VM"
    # -E preserves the forwarded env under sudo; the worker self-locates the repo from its own path.
    VM_TYPE=${VM_TYPE} vagrant ssh "${VM_NAME}" -c \
        "sudo -E env ${FWD[*]} bash '${INCLUSTER}'"
}

teardown() {
    if [ "${DESTROY}" = "1" ]; then
        log "destroying test VM"
        VM_TYPE=${VM_TYPE} vagrant destroy -f "${VM_NAME}" || true
    else
        log "VM left running (DESTROY=1 to remove it; 'VM_TYPE=test vagrant ssh ${VM_NAME}' to inspect)"
    fi
}

rc=0
up
run_incluster || rc=$?
teardown
if [ "${rc}" -eq 0 ]; then
    log "CLUSTER TEST PASSED"
else
    die "cluster test failed (rc=${rc}) - inspect with: VM_TYPE=test vagrant ssh ${VM_NAME}"
fi
