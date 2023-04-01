![Tracee Logo](docs/images/tracee.png)

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/releases)
[![License](https://img.shields.io/github/license/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/blob/main/LICENSE)
[![docker](https://badgen.net/docker/pulls/aquasec/tracee)](https://hub.docker.com/r/aquasec/tracee)

# Tracee: Runtime Security and Forensics using eBPF

Tracee uses eBPF technology to tap into your system and give you access to hundreds of events that help you understand how your system behaves.
In addition to basic observability events about system activity, Tracee adds a collection of sophisticated security events that expose more advanced behavioral patterns. You can also easily add your own events using the popular [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) language.
Tracee provides a rich filtering mechanism that allows you to eliminate noise and focus on specific workloads that matter most to you.

To learn more about Tracee, check out the [documentation](https://aquasecurity.github.io/tracee).

## Quickstart

You can easily start experimenting with Tracee using the Docker image as follows:

```console
docker run \
  --name tracee --rm -it \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /boot/config-$(uname -r):/boot/config-$(uname -r):ro \
  -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
  aquasec/tracee:$(uname -m)
```

To learn how to install Tracee in a production environment, [check out the Kubernetes guide](https://aquasecurity.github.io/tracee/latest/getting-started/kubernetes-quickstart).

## Pipeline protection with Tracee

Tracee can be used to protect GitHub Actions workflows against supply chain attacks. See the [tracee-action](https://github.com/aquasecurity/tracee-action) project for more information.

---

Tracee is an [Aqua Security](https://aquasec.com) open source project.  
Learn about our open source work and portfolio [Here](https://www.aquasec.com/products/open-source-projects/).  
Join the community, and talk to us about any matter in [GitHub Discussion](https://github.com/aquasecurity/tracee/discussions) or [Slack](https://slack.aquasec.com).  
