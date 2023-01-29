![Tracee Logo](images/tracee.png)

> Before moving on, make sure to give us a star at the
> [GitHub Project](https://github.com/aquasecurity/tracee/)
> if you liked it. That is important for us. Thank you!

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/aquasecurity/tracee)](https://goreportcard.com/report/github.com/aquasecurity/tracee)
[![License](https://img.shields.io/github/license/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/blob/main/LICENSE)
[![docker](https://badgen.net/docker/pulls/aquasec/tracee)](https://hub.docker.com/r/aquasec/tracee)

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

Watch a quick video demo of Tracee:

[![Tracee Live Demo AND Q&A](./images/tracee_video_thumbnail.png)](https://youtu.be/x2_iF0KjPKs?t=2971)

Check out the [Tracee video hub](https://info.aquasec.com/ebpf-runtime-security) for more videos.

## Quickstart (Kubernetes)

Tracee is designed to monitor hosts in kubernetes clusters. To see this in action check out the quickstart [here](./getting-started/kubernetes-quickstart).

## Quickstart (docker)

To get a closer feel for what tracee accomplishes, you can run tracee on your local machine. Follow along to the quickstart [here](./getting-started/docker-quickstart)

## Pipeline protection with Tracee

Tracee can be used to protect GitHub Actions workflows against supply chain attacks. See the [tracee-action](https://github.com/aquasecurity/tracee-action) project for more information.

---

Tracee is an [Aqua Security] open source project.
Learn about our open source work and portfolio [Here].
Join the community, and talk to us about any matter in [GitHub Discussion] or [Slack].

[Tracee-eBPF]: ./docs/tracing/index.md
[Tracee-Rules]: ./docs/detecting/index.md

[Aqua Security]: https://aquasec.com
[GitHub Discussion]: https://github.com/aquasecurity/tracee/discussions
[Slack]: https://slack.aquasec.com
[Here]: https://www.aquasec.com/products/open-source-projects/
