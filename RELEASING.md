# Releasing

1. Checkout a clean Tracee branch from `upstream` (instead of using your own).
   This will help with wrong tags you might have locally (by not uploading them
   by accident).

   ```console
   gh clone aquasec/tracee
   ```

1. Prepare release by creating the PR with the following changes
   1. Check if a libbpfgo update is needed (needs to be released first).
   1. Check if libbpf version is the same as libbpfgo's libbpf version.
   1. Update types module to latest.
   1. Update the container image tag, with the one to be released, at: `deploy/kubernetes/tracee/tracee.yaml`
   1. Update `home`, `version` and `appVersion` properties in [`deploy/helm/tracee/Chart.yaml`] -
      [example](https://github.com/aquasecurity/tracee/pull/2195)
   1. Create a PR with the tags bump

1. Run tests and checks
   1. Manually run a snapshot release from its workflow.
   1. Sanity checks features that might not have specific tests:
      1. multiple policy files simultaneously (check event results)
      1. network capture (pcap files)
      1. other capture (files, memory, etc...)
      1. other ...
   
1. Create a git tag and push it to the `upstream`. This will trigger the
   [`.github/workflows/release.yaml`] workflow.

   ```console
   git tag -v0.99.0
   git push upstream v0.99.0
   ```

1. Verify that the `release` workflow has built and published the artifacts.
   1. Tracee binaries (tracee, tracee-ebpf, tracee-static, tracee-ebpf-static,
      tracee-rules, signatures) in the form of a tar archive `tracee.<VERSION>.tar.gz`
   1. Source code zip and tar files
   1. Docker images pushed to the aquasec/tracee repository.
1. Publish the Helm chart by triggering workflow [`.github/workflows/publish-helm.yaml`].

[`.github/workflows/release.yaml`]: ./.github/workflows/release.yaml
[`.github/workflows/publish-helm.yaml`]: ./.github/workflows/publish-helm.yaml
[`deploy/helm/tracee/Chart.yaml`]: ./deploy/helm/tracee/Chart.yaml
