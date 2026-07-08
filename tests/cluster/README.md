# Cluster (k8s) test

End-to-end smoke test for Tracee on Kubernetes, in a throwaway VM:

1. bring up the Vagrant **test** VM (QEMU, defined in the repo `Vagrantfile`),
2. install single-node **k3s**,
3. build the local Tracee image and import it into k3s' containerd — or pull the released image,
4. `helm install` the chart from `deploy/helm/tracee` with the operator disabled
   (`operator.create=false`),
5. apply a **Policy** CRD (`examples/policies/yaml/k8s/context_comm.yaml` by default), then roll
   the tracee DaemonSet so it re-reads the CRD,
6. verify the DaemonSet is Ready and its stdout shows events for the policy.

Tracee reads Policy CRDs itself at boot; the tracee-operator's only job is to restart the
DaemonSet when a CRD changes, so the test does that restart itself and skips the operator (the CI
image then carries only the `tracee` binary).

## Run

```bash
tests/cluster/run.sh                 # full local-build cluster test in a fresh test VM
USE_RELEASED=1 tests/cluster/run.sh  # deploy docker.io/aquasec/tracee (deploy mechanics only)
KEEP=1 tests/cluster/run.sh          # leave the deployment up for inspection
DESTROY=1 tests/cluster/run.sh       # vagrant destroy the VM when done
REUSE=1 tests/cluster/run.sh         # skip 'vagrant up' if the VM is already running
```

`incluster.sh` can also be run directly on any Linux host that has docker + a real kernel
(it installs k3s locally). Knobs: `NAMESPACE`, `TRACEE_IMAGE`, `POLICY_FILE`, `READY_TIMEOUT`.

## First-run notes

This harness has not been executed end-to-end here — expect to adjust one or two things on
the first real run:

- **Image build** (`incluster.sh` Phase 2) uses `docker build -f
  builder/Dockerfile.alpine-tracee-container` (FLAVOR=tracee-core, BTFHUB=0). The test VM must
  carry the build toolchain (docker + clang/llvm + libbpf); if it doesn't, use
  `USE_RELEASED=1`. Adjust the build args to your setup if needed.
- **Verification** greps the Tracee pod's stdout for the policy's events. The chart is
  configured for `stdout` JSON output, so this works with the default `context_comm` policy
  (openat by `comm=ls`); change `POLICY_FILE` and the grep in `verify()` if you use another.

## In CI

`run.sh` (Vagrant/QEMU) can't run on stock GitHub runners (no nested KVM), but the runner is
already a real-kernel Linux VM, so `incluster.sh` runs on it directly. The
`.github/workflows/k8s-smoke.yaml` workflow (triggered on PRs that touch code/chart/harness) does
this cheaply for the **current PR code**:

1. compile `tracee` once on alpine (cached),
2. package the prebuilt binary into a COPY-only image (`builder/Dockerfile.ci`) — seconds, no
   recompile, unlike the full `Dockerfile.alpine-tracee-container`,
3. `SKIP_BUILD=1 TRACEE_IMAGE=... incluster.sh` imports that image and runs the smoke test.

Flip the workflow's `use_released` input to smoke the released image instead (deploy mechanics
only, no build). `SKIP_BUILD=1` also works locally: `docker build -f builder/Dockerfile.ci -t
tracee:pr .` (with a prebuilt `dist/`) then `sudo SKIP_BUILD=1 TRACEE_IMAGE=tracee:pr
tests/cluster/incluster.sh`.

## Why this exists

It validates the k8s deploy + CRD path against the current code: the chart deploys, tracee loads
a Policy CRD, and traces per that policy. It's also groundwork for the future in-daemon CRD watch
(no-restart policy updates via the runtime ApplyPolicy path), which would remove the restart step.
