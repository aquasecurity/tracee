![Tracee Logo](images/tracee.png)

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/aquasecurity/tracee)](https://goreportcard.com/report/github.com/aquasecurity/tracee)
[![License](https://img.shields.io/github/license/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/blob/main/LICENSE)
[![docker](https://badgen.net/docker/pulls/aquasec/tracee)](https://hub.docker.com/r/aquasec/tracee)

# Tracee: Linux Runtime Security and Forensics using eBPF

Tracee is a Runtime Security and forensics tool for Linux. It is using Linux eBPF technology to trace your system and applications at runtime, and analyze collected events to detect suspicious behavioral patterns.

Tracee is delivered as a Docker image that once run, will start to monitor the OS and detect suspicious behavior based on a pre-defined set of behavioral patterns.

Tracee is composed of the following sub-projects:

- [Tracee-eBPF](ebpf/index.md) - Linux Tracing and Forensics using eBPF
- [Tracee-Rules](rules/index.md) - Runtime Security Detection Engine
- [libbpgo](libbpfgo) - Go library for eBPF programming using Linux's [libbpf](https://github.com/libbpf/libbpf)

