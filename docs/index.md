![Tracee Logo](images/tracee.png)

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/aquasecurity/tracee)](https://goreportcard.com/report/github.com/aquasecurity/tracee)
[![License](https://img.shields.io/github/license/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/blob/main/LICENSE)
[![docker](https://badgen.net/docker/pulls/aquasec/tracee)](https://hub.docker.com/r/aquasec/tracee)

# Tracee: Runtime Security and Forensics using eBPF

Tracee is a Runtime Security and forensics tool for Linux. It is using Linux eBPF technology to trace your system and applications at runtime, and analyze collected events to detect suspicious behavioral patterns. It is delivered as a Docker image that monitors the OS and detects suspicious behavior based on a predefined set of behavioral patterns.

Watch a quick video demo of Tracee: <br>
<a href="https://youtu.be/9qxaOYto_5g"><img src="http://i3.ytimg.com/vi/9qxaOYto_5g/maxresdefault.jpg" width="400"></a>

Check out the [Tracee video hub](https://info.aquasec.com/ebpf-runtime-security) for more.

## Quickstart

Before you proceed, make sure you follow the [minimum requirements for running Tracee](install/prerequisites.md).

If running on __BTF enabled kernel__:

```bash
docker run --name tracee --rm -it --pid=host --cgroupns=host --privileged \
  -v /tmp/tracee:/tmp/tracee \
  aquasec/tracee:{{ git.tag[1:] }}
```

!!! note
    Running with BTF requires access to the kernel configuration file. Depending on the Linux distribution it can be in either `/proc/config.gz` (which docker mounts by default) or `/boot/config-$(uname -r)` (which must be mounted explicitly).

If running on __BTF disabled kernel__:
```bash
docker run --name tracee --rm -it --pid=host --cgroupns=host --privileged \
  -v /tmp/tracee:/tmp/tracee \
  -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  aquasec/tracee:{{ git.tag[1:] }}
```

!!! note
    You may need to change the volume mounts for the kernel headers based on your setup. See [Linux Headers](install/headers.md) section for more info.

This will run Tracee with default settings and start reporting detections to standard output.
In order to simulate a suspicious behavior, you can run `strace ls` in another terminal, which will trigger the "Anti-Debugging" signature, which is loaded by default.

## Trace

In some cases, you might want to leverage Tracee's eBPF event collection capabilities directly, without involving the detection engine. This might be useful for debugging/troubleshooting/analysis/research/education. In this case you can run Tracee with the `trace` sub-command, which will start dumping raw data directly into standard output. There are many configurations and options available so you can control exactly what is being collected and how. see the Documentation or add the `--help` flag for more.

## Components

Tracee is composed of the following sub-projects, which are hosted in the aquasecurity/tracee repository:

- [Tracee-eBPF](https://github.com/aquasecurity/tracee/tree/{{ git.tag }}/tracee-ebpf) - Linux Tracing and Forensics using eBPF
- [Tracee-Rules](https://github.com/aquasecurity/tracee/tree/{{ git.tag }}/tracee-rules) - Runtime Security Detection Engine

---

Tracee is an [Aqua Security] open source project.  
Learn about our open source work and portfolio [here](https://www.aquasec.com/products/open-source-projects/).  
Join the community, and talk to us about any matter in [GitHub Discussion] or [Slack].

[Aqua Security]: https://aquasec.com
[GitHub Discussion]: https://github.com/aquasecurity/tracee/discussions
[Slack]: https://slack.aquasec.com