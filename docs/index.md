![Tracee Logo](images/tracee.png)

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/aquasecurity/tracee)](https://goreportcard.com/report/github.com/aquasecurity/tracee)
[![License](https://img.shields.io/github/license/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/blob/main/LICENSE)
[![docker](https://badgen.net/docker/pulls/aquasec/tracee)](https://hub.docker.com/r/aquasec/tracee)

# Tracee: Runtime Security and Forensics using eBPF

Tracee is a Runtime Security and forensics tool for Linux. It is using Linux
eBPF technology to trace your system and applications at runtime, and analyze
collected events to detect suspicious behavioral patterns. It is delivered as a
Docker image that monitors the OS and detects suspicious behavior based on a
predefined set of behavioral patterns.

Watch a quick video demo of Tracee: <br>
<a href="https://youtu.be/x2_iF0KjPKs?t=2971"><img src="https://i2.paste.pics/b755d5ee03048e3782f42da9870630eb.png?trs=a87585fdab9f70820cff773222a23ad3bbbc31d0b579bdc1b0ad91aa0cc19ecf" width="400"></a>

Check out the [Tracee video hub](https://info.aquasec.com/ebpf-runtime-security) for more.

## Quickstart

Before you proceed, make sure you follow the [minimum requirements for running Tracee](install/prerequisites.md).

1. Running **tracee:latest**

   ```bash
   $ docker run \
        --name tracee --rm -it \
        --pid=host --cgroupns=host --privileged \
        -v /etc/os-release:/etc/os-release-host:ro \
        -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
        aquasec/tracee:{{ git.tag[1:] }}
   ```

2. Running **tracee:full**

   ```bash
   docker run --name tracee --rm -it \
       --pid=host --cgroupns=host --privileged \
       -v /etc/os-release:/etc/os-release-host:ro \
       -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
       -v /usr/src:/usr/src:ro \
       -v /lib/modules:/lib/modules:ro \
       -v /tmp/tracee:/tmp/tracee:rw \
        aquasec/tracee:full-{{ git.tag[1:] }}
   ```

!!! note
    The default (latest) image is **lightweight** and **portable**. It is supposed to
    support different kernel versions without having to build source code. If
    the host kernel does not support BTF then you may use the **full** container 
    image. The full container will compile an eBPF object during startup, if you do 
    not have one already cached in `/tmp/tracee`.

!!! note
    You may need to change the volume mounts for the kernel headers based on
    your setup. See [Linux Headers](./install/headers.md) section for more
    info.

This will run Tracee with default settings and start reporting detections to
standart output. In order to simulate a suspicious behavior, you can simply
run:

```strace ls```

in another terminal. This will trigger the "Anti-Debugging" signature, which is
loaded by default AND you will get a warning.

## Trace

In some cases, you might want to leverage Tracee's eBPF event collection
capabilities directly, without involving the detection engine. This might be
useful for debugging/troubleshooting/analysis/research/education. In this case,
you can run tracee exporting `TRACEE_EBPF_ONLY=1` environment variable.

```bash
$ docker run \
    --name tracee --rm -it \
    --pid=host --cgroupns=host --privileged \
    -v /etc/os-release:/etc/os-release-host:ro \
    -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
    -e TRACEE_EBPF_ONLY=1 \
    aquasec/tracee:{{ git.tag[1:] }}
```

!!! note
    See documentation or add the `--help` flag for more.

## Components

Tracee is composed of the following sub-projects, which are hosted in the
aquasecurity/tracee repository:

- [Tracee-eBPF](https://github.com/aquasecurity/tracee/tree/{{ git.tag }}/tracee-ebpf) - Linux Tracing and Forensics using eBPF
- [Tracee-Rules](https://github.com/aquasecurity/tracee/tree/{{ git.tag }}/tracee-rules) - Runtime Security Detection Engine

---

Tracee is an [Aqua Security] open source project. Learn about our open source
work and portfolio [Here]. Join the community, and talk to us about any matter
in [GitHub Discussion] or [Slack].

[Aqua Security]: https://aquasec.com
[GitHub Discussion]: https://github.com/aquasecurity/tracee/discussions
[Slack]: https://slack.aquasec.com
[Here]: https://www.aquasec.com/products/open-source-projects/
