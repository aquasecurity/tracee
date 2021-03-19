![Tracee Logo](images/tracee.png)

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/aquasecurity/tracee)](https://goreportcard.com/report/github.com/aquasecurity/tracee)
[![License](https://img.shields.io/github/license/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/blob/main/LICENSE)
[![docker](https://badgen.net/docker/pulls/aquasec/tracee)](https://hub.docker.com/r/aquasec/tracee)

# Tracee: Linux Runtime Security and Forensics using eBPF

Tracee is a Runtime Security and forensics tool for Linux. It is using Linux eBPF technology to trace your system and applications at runtime, and analyze collected events to detect suspicious behavioral patterns.

Tracee is delivered as a Docker image that once run, will start to monitor the OS and detect suspicious behavior based on a pre-defined set of behavioral patterns.

Tracee is composed of the following sub-projects:
- [Tracee-eBPF](tracee-ebpf) - Linux Tracing and Forensics using eBPF
- [Tracee-Rules](tracee-rules) - Runtime Security Detection Engine
- [libbpgo](libbpfgo) - Go library for eBPF programming using Linux's [libbpf](https://github.com/libbpf/libbpf)

## Getting started

### Prerequisites

- Linux kernel version >= 4.18
- Relevant kernel headers available under conventional location (see [Linux Headers](#Linux-Headers) section for info)
- libc, and the libraries: libelf and zlib
- Gnu Make >= 4.3, needed for "group targets" support.
- clang >= 9
- go >= 1.16, needed for embedded support.

Exceptions:

- Tracee supports loading a pre-compiled eBPF file, in which case the kernel headers are required only for the one-time compilation, and not at runtime. See Setup Options for more info.
- When using Tracee's Docker image, all of the aforementioned requirements are built into the image. The only requirement left is the kernel headers or the pre-built eBPF. See Setup Options for more info.

### Quickstart with Docker

```bash
docker run --name tracee --rm --privileged -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro -v /tmp/tracee:/tmp/tracee aquasec/tracee:latest
```

> Note: You may need to change the volume mounts for the kernel headers based on your setup. See [Linux Headers](#Linux-Headers) section for info.

This will run Tracee with no arguments, which defaults to loading the default set of rules (see below), and to report detections on standard output (can be customized).
In order to simulate a suspicious behavior, you can run `strace ls` in another terminal, which will trigger the "Anti-Debugging" signature, which is loaded by default.

### Rules

To view the list of available rules, run the container with the `--list` flag.

We are currently working on creating a library of behavioral signature detections. Currently, the following are available:

Name | Description | Tags
 --- | --- | --- |
Standard Input/Output Over Socket | Redirection of process's standard input/output to socket | "linux", "container"
Anti-Debugging | Process uses anti-debugging technique to block debugger | "linux", "container"
Code injection | Possible code injection into another process | "linux", "container"
Dynamic Code Loading | Writing to executable allocated memory region | "linux", "container"
Fileless Execution | Executing a precess from memory, without a file in the disk | "linux", "container"
kernel module loading | Attempt to load a kernel module detection | "linux", "container"
LD_PRELOAD | Usage of LD_PRELOAD to allow hooks on process | "linux", "container"

### Integrations

Tracee can notify a web service when a detection is made using a custom webhook. You can configure Tracee's webhook settings using the following flags:

Flag name | Description | Example
--- | --- | ---
`--webhook-url` | The webhook URL | `--webhook-url http://my.webhook/endpoint`
`--webhook-template` | Path to Go-template that formats the payload to send. Tracee's [Finding](https://github.com/aquasecurity/tracee/blob/28fbc66be8c9f3efa53f617a654cafe7421e8c70/tracee-rules/types/types.go#L46-L50) type is available to use within the template | `--webhook-template /path/to/my.tmpl` <br> See template examples [here](tracee-rules/templates/).
`--webhook-content-type` | If present, will set the Content-Type HTTP header to match the provided template | `--webhook-content-type application/json`

A popular webhook server that can be used with Tracee is [falcosidekick](https://github.com/falcosecurity/falcosidekick), which can send detection events into other systems of your choosing (for example Slack, Teams, Datadog, Prometheus, Email, Elasticsearch, PagerDuty, and many more). For more information on falcosidekick see [here](https://github.com/falcosecurity/falcosidekick/blob/master/config_example.yaml).

### Setup options

Tracee is leveraging Linux's eBPF technology, which is kernel and version sensitive, and therefore needs to be specifically compiled for your hosts.

The easiest way to get started is to just let Tracee build the eBPF program for you automatically when it starts, as demonstrated by the [Quickstart](#quickstart-with-docker).  
Alternatively, you can pre-compile the eBPF program, and provide it to Tracee. There are some benefits to this approach as you will not need clang and kernel headers at runtime anymore, as well as reduced risk of invoking an external program at runtime.

You can build the eBPF program in the following ways:
1. Clone the repo including submodules (`git clone --recursive https://github.com/aquasecurity/tracee.git`) and `make bpf`.
2. `make bpf DOCKER=1` to build in a Docker container which includes all development tooling.

Running this will produce a file called `tracee.bpf.$kernelversion.$traceeversion.o` under the `dist` directory.  
Once you have the eBPF program artifact, you can provide it to Tracee in any of the following locations:
1. Path specified in `TRACEE_BPF_FILE` environment variable
2. `/tmp/tracee`

In this case, the full Docker image can be replaced by the lighter-weight `aquasec/tracee:slim` image. This image cannot build the eBPF program on its own, and is meant to be used when you have already compiled the eBPF program beforehand.

#### Running in container

Tracee uses a filesystem directory, by default `/tmp/tracee` as a work space and for default search location for file based user input. When running in a container, it's useful to mount this directory in, so that the artifacts are accessible after the container exits. For example, you can add this to the docker run command `-v /tmp/tracee:/tmp/tracee`.

If running in a container, regardless if it's the full or slim image, it's advisable to reuse the eBPF program across runs by mounting it from the host to the container. This way if the container builds the eBPF program it will be persisted on the host, and if the eBPF program already exists on the host, the container will automatically discover it. If you've already mounted the `/tmp/tracee` directory from the host (like suggested by the [quickstart-with-docker](#quickstart), you're good to go, since Tracee by default will use this location for the eBPF program. You can also mount the eBPF program file individually if it's stored elsewhere (e.g in a shared volume), for example: `-v /path/to/tracee.bpf.1_2_3.4_5_6.o:/some/path/tracee.bpf.1_2_3.4_5_6.o -e TRACEE_BPF_FILE=/some/path`. 

If you are building the eBPF program in a container, you'll need to make the kernel headers available in the container. The quickstart example has broader mounts that works in a variety of cases, for demonstration purposes. If you want, you can narrow those mounts down to the specific directory that contains the headers on your setup, for example: `-v /path/to/headers:/myheaders -e KERN_HEADERS=/myheaders`. As mentioned before, a better practice for production is to pre-compile the eBPF program, in which case the kernel headers are not needed at runtime.

#### Permissions

If Tracee is not actually tracing, it doesn't need privileges. For example, just building the eBPF program, or listing the available options, can be done with a regular user.  
For actually tracing, Tracee needs to run with sufficient capabilities: 
- `CAP_SYS_RESOURCE` (to manage eBPF maps limits)
- `CAP_BPF`+`CAP_TRACING` which are available on recent kernels (>=5.8), or `SYS_ADMIN` on older kernels (to load and attach the eBPF programs).

Alternatively, running as `root` or with the `--privileged` flag of Docker, is an easy way to start.

#### Linux Headers

In order to compile the eBPF program, Tracee needs some of the Linux kernel headers. Depending on your Linux distribution, there may be different ways to obtain them.  

- On Docker for MAC follow the [following guidelines](docker-mac.md).
- On Ubuntu/Debian/Arch/Manjaro install the `linux-headers` package.
- On CentOS/Fedora install the `kernel-headers` and `kernel-devel` packages.

Normally the files will be installed in `/lib/modules/${kernel_version}/build` which is where Tracee expects them. If you have the headers elsewhere, you can set the `KERN_HEADERS` environment variable with the correct location.

> Note that it's important that the kernel headers match the exact version of kernel you are running. To check the current kernel version, run the command `uname -r`. To install a specific kernel headers version append the version to the package name: `linux-headers-$(uname -r)`.

> Note that more often than not the kernel headers files contains filesystem links to other files in other directories. Therefore, when passing the kernel headers to Tracee docker container, make sure all the necessary directories are mounted. This is why the quickstart example mounts `/usr/src` in addition to `/lib/modules`.
