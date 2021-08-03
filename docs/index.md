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

```bash
docker run --name tracee --rm --privileged -v /boot/config-$(uname -r):/boot/config-$(uname -r):ro -it aquasec/tracee:latest
```

This will run Tracee with the portable CO:RE bpf object and default settings. It will start reporting detections to standard output.  
In order to simulate a suspicious behavior, you can run `strace ls` in another terminal, which will trigger the "Anti-Debugging" signature, which is loaded by default.

> Note: You may need to change the volume mounts for the kernel headers based on your setup if the kernel doesn't have BTF enabled. See [Linux Headers](install/headers.md) section for more info.

## Trace

In some cases, you might want to leverage Tracee's eBPF event collection capabilities directly, without involving the detection engine. This might be useful for debugging/troubleshooting/analysis/research/education. In this case you can run Tracee with the `trace` sub-command, which will start dumping raw data directly into standard output. There are many configurations and options available so you can control exactly what is being collected and how. see the Documentation or add the `--help` flag for more.

## Components

Tracee is composed of the following sub-projects, which are hosted in the aquasecurity/tracee repository:
- [Tracee-eBPF](https://github.com/aquasecurity/tracee/tree/main/tracee-ebpf) - Linux Tracing and Forensics using eBPF
- [Tracee-Rules](https://github.com/aquasecurity/tracee/tree/main/tracee-rules) - Runtime Security Detection Engine
