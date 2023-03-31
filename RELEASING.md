# Releasing

1. Checkout your fork and make sure it's up-to-date with the `upstream`

   ```console
   git remote -v
   ```

   ```text
   origin     git@github.com:<your account>/tracee.git (fetch)
   origin     git@github.com:<your account>/tracee.git (push)
   upstream   git@github.com:aquasecurity/tracee.git (fetch)
   upstream   git@github.com:aquasecurity/tracee.git (push)
   ```

   ```console
   git pull -r
   git fetch upstream
   git merge upstream/main
   git push
   ```

1. Prepare release by creating the PR with the following changes
   1. Update the libbpfgo module
   2. Update the types module
   3. Update the container image tag in the following files
      1. `deploy/kubernetes/kustomize/base/tracee.yaml`
      2. `cd deploy/kubernetes/ && ./update-static.sh` to generate all static files with the proper tag
   4. Update `home`, `version` and `appVersion` properties in [`deploy/helm/tracee/Chart.yaml`] - [example](https://github.com/aquasecurity/tracee/pull/2195)
	 5. Create a PR with the tags bump
1. Run tests and checks
   1. Check that there are no verifier issues when choosing all events in tracee (using `--filter e='*'`)
   1. Check both CO-RE and non CO-RE builds
   1. Run all unit, integration, and e2e tests
   1. Sanity checks for different special features
      1. capture artifacts (files, memory, net, etc...)
      1. table/json/gob printers output
      1. tracee with various filters
   1. Check that docker images build correctly
1. Run the above tests/checks for three different kernel versions include old kernels (4.18/4.19) and new ones (5.10+)
1. Review and merge the PR (make sure all tests are passing)
1. Update your fork again
   
   ```console
   git pull -r
   git fetch upstream
   git merge upstream/main
   git push
   ```

1. Create an annotated git tag and push it to the `upstream`. This will trigger the [`.github/workflows/release.yaml`] workflow

   ```console
   git tag -v0.8.1 -m 'Release v0.8.1'
   git push upstream v0.8.1
   ```

1. Verify that the `release` workflow has built and published the following artifacts
   1. Tracee binaries (tracee-ebpf, tracee-rules, signatures) in the form of a tar archive `tracee.<VERSION>.tar.gz`
   1. Source code zip and tar files
   1. Docker images pushed to the aquasec/tracee repository (`docker.io/aquasec/tracee:<VERSION>` and `docker.io/aquasec/tracee:full-<VERSION>`)
1. Publish the Helm chart by manually triggering the [`.github/workflows/publish-helm.yaml`] workflow

[`.github/workflows/release.yaml`]: ./.github/workflows/release.yaml
[`.github/workflows/publish-helm.yaml`]: ./.github/workflows/publish-helm.yaml
[`deploy/helm/tracee/Chart.yaml`]: ./deploy/helm/tracee/Chart.yaml
