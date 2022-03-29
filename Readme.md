![Tracee Logo](docs/images/tracee.png)

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/aquasecurity/tracee)](https://goreportcard.com/report/github.com/aquasecurity/tracee)
[![License](https://img.shields.io/github/license/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/blob/main/LICENSE)
[![docker](https://badgen.net/docker/pulls/aquasec/tracee)](https://hub.docker.com/r/aquasec/tracee)
[![Scheduled Signatures Test](https://github.com/aquasecurity/tracee/actions/workflows/scheduled-signatures-test.yaml/badge.svg)](https://github.com/aquasecurity/tracee/actions/workflows/scheduled-signatures-test.yaml)

# Tracee: Runtime Security and Forensics using eBPF

Tracee is a Runtime Security and forensics tool for Linux. It is using Linux eBPF technology to trace your system and applications at runtime, and analyze collected events to detect suspicious behavioral patterns. It is delivered as a Docker image that monitors the OS and detects suspicious behavior based on a pre-defined set of behavioral patterns.

Watch a quick video demo of Tracee: <br>
<a href="https://youtu.be/9qxaOYto_5g"><img src="http://i3.ytimg.com/vi/9qxaOYto_5g/maxresdefault.jpg" width="400"></a>

Check out the [Tracee video hub](https://info.aquasec.com/ebpf-runtime-security) for more.

## Documentation

The full documentation of Tracee is available at [https://aquasecurity.github.io/tracee/latest](https://aquasecurity.github.io/tracee/latest). You can use the version selector on top to view documentation for a specific version of Tracee.

## Quickstart

Before you proceed, make sure you follow the [minimum requirements for running Tracee](https://aquasecurity.github.io/tracee/latest/install/prerequisites/).

If running on __BTF enabled kernel__:

```
docker run \
  --name tracee --rm -it \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
  aquasec/tracee:latest
```

> Note: Running with BTF requires access to the kernel configuration file. Depending on the Linux distribution it can be
> in either `/proc/config.gz` (which docker mounts by default) or `/boot/config-$(uname -r)` (which must be mounted explicitly).

If running on __BTF disabled kernel__:

```
docker run --name tracee --rm -it \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
  -v /usr/src:/usr/src:ro \
  -v /lib/modules:/lib/modules:ro \
  -v /tmp/tracee:/tmp/tracee:rw \
  aquasec/tracee:full
```

> Note: You may need to change the volume mounts for the kernel headers based on your setup. See [Linux Headers] section
> for more info.

This will run Tracee with default settings and start reporting detections to standard output.  
In order to simulate a suspicious behavior, you can run `strace ls` in another terminal, which will trigger the
"Anti-Debugging" signature, which is loaded by default, and you will get a warning:

```
INFO: probing tracee-ebpf capabilities...
INFO: starting tracee-ebpf...
INFO: starting tracee-rules...
Loaded 14 signature(s): [TRC-1 TRC-13 TRC-2 TRC-14 TRC-3 TRC-11 TRC-9 TRC-4 TRC-5 TRC-12 TRC-8 TRC-6 TRC-10 TRC-7]
Serving metrics endpoint at :3366
Serving metrics endpoint at :4466

*** Detection ***
Time: 2022-03-25T08:04:22Z
Signature ID: TRC-2
Signature: Anti-Debugging
Data: map[]
Command: strace
Hostname: ubuntu-impish
```

## Trace

In some cases, you might want to leverage Tracee's eBPF event collection capabilities directly, without involving the
detection engine. This might be useful for debugging/troubleshooting/analysis/research/education. In this case you can
run Tracee with the `trace` sub-command, which will start dumping raw data directly into standard output. There are many
configurations and options available so you can control exactly what is being collected and how. see the Documentation
or add the `--help` flag for more.

## Components

Tracee is composed of the following sub-projects, which are hosted in the aquasecurity/tracee repository:
- [Tracee-eBPF](cmd/tracee-ebpf) - Linux Tracing and Forensics using eBPF
- [Tracee-Rules](cmd/tracee-rules) - Runtime Security Detection Engine

---

Tracee is an [Aqua Security](https://aquasec.com) open source project.  
Learn about our open source work and portfolio [here](https://www.aquasec.com/products/open-source-projects/).  
Contact us about any matter by opening a GitHub Discussion [here](https://github.com/aquasecurity/tracee/discussions).

[Linux Headers]: https://aquasecurity.github.io/tracee/latest/install/headers
