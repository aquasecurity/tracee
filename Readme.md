![Tracee Logo](images/tracee.png)

# Tracee: Linux Runtime security and forensics using eBPF

Tracee is a Runtime Security and forensics tool for Linux. It is using Linux eBPF technology to trace your system and applications at runtime, and analyze collected events to detect suspicious behavioral patterns.

This repo contains the following projects:
- [Tracee-eBPF](tracee-ebpf) - Container and system tracing using eBPF
- [Tracee-Rules](tracee-rules) - Runtime security detection engine
- [libbpgo](libbpfgo) - Go library for eBPF programming using Linux's [libbpf](https://github.com/libbpf/libbpf)

The repo is currently in a state of transition into a monorepo containing these multiple projects. If you are looking for the previous "Tracee" tool, look in the "tracee-ebpf" directory.
