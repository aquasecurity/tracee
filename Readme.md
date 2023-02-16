![Tracee Logo](docs/images/tracee.png)

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/aquasecurity/tracee)](https://goreportcard.com/report/github.com/aquasecurity/tracee)
[![License](https://img.shields.io/github/license/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/blob/main/LICENSE)
[![docker](https://badgen.net/docker/pulls/aquasec/tracee)](https://hub.docker.com/r/aquasec/tracee)
[![Release Snapshot](https://github.com/aquasecurity/tracee/actions/workflows/release-snapshot.yaml/badge.svg)](https://github.com/aquasecurity/tracee/actions/workflows/release-snapshot.yaml)
[![OS Packages (DAILY)](https://github.com/aquasecurity/tracee/actions/workflows/test-os-packaging-daily.yaml/badge.svg)](https://github.com/aquasecurity/tracee/actions/workflows/test-os-packaging-daily.yaml)
[![Tests (DAILY)](https://github.com/aquasecurity/tracee/actions/workflows/test-daily.yaml/badge.svg)](https://github.com/aquasecurity/tracee/actions/workflows/test-daily.yaml)

# Tracee: Runtime Security and Forensics using eBPF

Tracee is a runtime security and forensics tool for Linux based cloud deployments.
It uses **eBPF** to trace the host OS and applications **at runtime**, and analyzes
collected events in order to detect **suspicious behavioral patterns**. It can be
run as a daemon-set in your kubernetes environment, but is flexible to be run for
many purposes on any Linux based hosts. It can be delivered via Helm, as a docker
container, or as a small set of static binaries.

The goal of Tracee is to serve as an easy to use and effective solution for learning 
when cloud native attacks occur in your environment. By leveraging Aqua's advanced 
security research, performant eBPF based detection, and cloud native first
approach Tracee makes runtime detection accesible, powerful, and effective.

## Documentation

The full documentation of Tracee is available at
[https://aquasecurity.github.io/tracee/dev](https://aquasecurity.github.io/tracee/dev).
You can use the version selector on top to view documentation for a specific
version of Tracee.

## Quickstart (Kubernetes)

Tracee is designed to monitor hosts in kubernetes clusters. To see this in action check out the quickstart [here](./docs/getting-started/kubernetes-quickstart.md).

## Quickstart (docker)

To get a closer feel for what tracee accomplishes, you can run tracee on your local machine. Follow along to the quickstart [here](./docs/getting-started/docker-quickstart.md)

Execute docker container with the word `trace` as an initial argument, and
**tracee-ebpf** will be executed, instead of the full tracee detection engine.

```text
docker run \
  --name tracee --rm -it \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
  aquasec/tracee:latest \
  trace
```

## Pipeline protection with Tracee

Tracee can be used to protect GitHub Actions workflows against supply chain attacks. See the [tracee-action](https://github.com/aquasecurity/tracee-action) project for more information.

---

Tracee is an [Aqua Security] open source project.
Learn about our open source work and portfolio [Here].
Join the community, and talk to us about any matter in [GitHub Discussion] or [Slack].

[Tracee-eBPF]: https://aquasecurity.github.io/tracee/dev/docs/tracing/
[Tracee-Rules]: https://aquasecurity.github.io/tracee/dev/docs/detecting/

[Aqua Security]: https://aquasec.com
[GitHub Discussion]: https://github.com/aquasecurity/tracee/discussions
[Slack]: https://slack.aquasec.com
[Here]: https://www.aquasec.com/products/open-source-projects/
