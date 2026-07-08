# Cluster (k8s) test

End-to-end smoke test for Tracee on Kubernetes, in a throwaway VM:

1. bring up the Vagrant **test** VM (QEMU, defined in the repo `Vagrantfile`),
2. install single-node **k3s**,
3. build the local Tracee image (one image carries both the `tracee` and `tracee-operator`
   binaries) and import it into k3s' containerd — or pull the released image,
4. `helm install` the chart from `deploy/helm/tracee`,
5. apply a **Policy** CRD (`examples/policies/yaml/k8s/context_comm.yaml` by default),
6. verify the Tracee DaemonSet is Ready and its stdout shows events for the policy.

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

## Why this exists

It's the groundwork for validating the k8s/operator path — including the future in-daemon CRD
watch (no-restart policy updates). Today it validates the current operator + CRD deployment.
