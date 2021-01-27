![Tracee Logo](images/tracee.png)

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/aquasecurity/tracee)](https://goreportcard.com/report/github.com/aquasecurity/tracee)
[![License](https://img.shields.io/github/license/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/blob/main/LICENSE)
[![docker](https://badgen.net/docker/pulls/aquasec/tracee)](https://hub.docker.com/r/aquasec/tracee)

# Tracee: Linux Runtime Security and Forensics using eBPF

Tracee is a Runtime Security and forensics tool for Linux. It is using Linux eBPF technology to trace your system and applications at runtime, and analyze collected events to detect suspicious behavioral patterns.

This repo contains the following projects:
- [Tracee-eBPF](tracee-ebpf) - Linux Tracing and Forensics using eBPF
- [Tracee-Rules](tracee-rules) - Runtime Security Detection Engine
- [libbpgo](libbpfgo) - Go library for eBPF programming using Linux's [libbpf](https://github.com/libbpf/libbpf)

The repo is currently in a state of transition into a monorepo containing these multiple projects. If you are looking for the previous "Tracee" tool, look in the "tracee-ebpf" directory.
