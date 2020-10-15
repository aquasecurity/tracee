![Tracee Logo](images/tracee.png)

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/aquasecurity/tracee)](https://goreportcard.com/report/github.com/aquasecurity/tracee)
[![License](https://img.shields.io/github/license/aquasecurity/tracee)](https://github.com/aquasecurity/tracee/blob/master/LICENSE)
[![docker](https://badgen.net/docker/pulls/aquasec/tracee)](https://hub.docker.com/r/aquasec/tracee)

# Tracee - Container and system tracing using eBPF

Tracee is a lightweight and easy to use container and system tracing tool. It allows you to observe system calls and other system events in real-time. A unique feature of Tracee is that it will only trace newly created processes and containers (that were started after Tracee has started), in order to help the user focus on relevant events instead of every single thing that happens on the system (which can be overwhelming). Adding new events to Tracee (especially system calls) is straightforward, and will usually require no more than adding few lines of code.

Other than tracing, Tracee is also capable of capturing files written to disk or memory ("fileless"), and extracting binaries that are dynamically loaded to an application's memory (e.g. when an application uses a packer). With these features, it is possible to quickly gain insights about the running processes that previously required the use of dynamic analysis tools and special knowledge.

[Check out this quick demo of tracee](https://youtu.be/WTqE2ae257o)

## Getting started

### Prerequisites

To run, Tracee requires the following:
- Linux kernel version > 4.14
- Kernel headers
- C standard library (currently tested with glibc)
- [BCC](https://github.com/iovisor/bcc)

### Getting Tracee

You can get Tracee in any of the following ways:
1. Download the binary from the GitHub Releases tab (`tracee.tar.gz`).
2. Use the docker image from Docker Hub: `aquasec/tracee`. The image already includes libc and bcc but you will need to mount the kernel headers in (see below for example).
3. Build from source, using `make build` (or via Docker using `make build-docker`).

### Permissions

If you use the Tracee binary, you'll need to run it with root permissions in order to load the eBPF code. 
If you use the Docker container, you should run it with the `--privileged` flag.

### Quickstart with Docker

We will use the Tracee Docker image, which includes glibc and BCC. The host that Docker is running on needs to satisfy the other requirements, kernel version and kernel headers. If you use a recent version of Ubuntu, you are good to go as it satisfies those requirements, but any other Linux distribution will work as well.
To run Tracee using docker:

```bash
docker run --name tracee --rm --privileged --pid=host -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro aquasec/tracee:latest
```

This will run Tracee with no arguments which will collect all events from all newly created processes and print them as a table to the standard output.

Here is how the output looks:

```
TIME(s)        UID    COMM             PID     TID     RET             EVENT                ARGS
176751.746515  1000   zsh              14726   14726   0               execve               pathname: /usr/bin/ls, argv: [ls]
176751.746772  1000   zsh              14726   14726   0               security_bprm_check  pathname: /usr/bin/ls, dev: 8388610, inode: 777
176751.747044  1000   ls               14726   14726  -2               access               pathname: /etc/ld.so.preload, mode: R_OK
176751.747077  1000   ls               14726   14726   0               security_file_open   pathname: /etc/ld.so.cache, flags: O_RDONLY|O_LARGEFILE, dev: 8388610, inode: 533737
...
```

### Understanding the output

Each line is a single event collected by Tracee, with the following information:

1. TIME - shows the event time relative to system boot time in seconds
2. UID - real user id (in host user namespace) of the calling process
3. COMM - name of the calling process
4. PID - pid of the calling process
5. TID - tid of the calling thread
6. RET - value returned by the function
7. EVENT - identifies the event (e.g. syscall name)
8. ARGS - list of arguments given to the function

When using table-verbose output, the following information is added:

1. UTS_NAME - uts namespace name. As there is no container id object in the kernel, and docker/k8s will usually set this to the container id, we use this field to distinguish between containers.
2. MNT_NS - mount namespace inode number.
3. PID_NS - pid namespace inode number. In order to know if there are different containers in the same pid namespace (e.g. in a k8s pod), it is possible to check this value
4. PPID - parent pid of the calling process


## Configuration flags

- Use `--help` to see a full description of all options.
Here are a few commonly useful flags:
- `--trace` Sets the trace mode. For more information see [Trace Mode Configuration](#Trace-Mode-Configuration) below
- `--event` allows you to specify a specific event to trace. You can use this flag multiple times, for example `--event execve --event openat`.
- `--list` lists the events available for tracing, which you can provide to the `--event` flag.
- `--output` lets you control the output format, for example `--output json` will output as JSON lines instead of table.
- `--capture` capture artifacts that were written, executed or found suspicious, and save them to the output directory. Possible values are: 'write'/'exec'/'mem'/'all'

### Trace Mode Configuration

`--trace` and `-t` set whether to trace events based upon system-wide processes, or Containers. It also used to set whether to trace only new processes/containers (default), existing processes/containers, or specific processes.
Tracing specific containers is currently not possible. The possible options are:

Option | Flag(s):
--- | --- |
Trace new processes (default) | no `--trace` flag, `--trace p`, `--trace process` or `--trace process:new`
Trace existing and new processes | `--trace process:all`
Trace specific PIDs | `--trace process:<pid>,<pid2>,...` or `--trace p:<pid>,<pid2>,...`
Trace new containers | `--trace c`, `--trace container` or `--trace container:new`
Trace existing and new containers | `--trace container:all`

You can also use `-t` e.g. `-t p:all`


## Secure tracing

When Tracee reads information from user programs it is subject to a race condition where the user program might be able to change the arguments after Tracee has read them. For example, a program invoked `execve("/bin/ls", NULL, 0)`, Tracee picked that up and will report that, then the program changed the first argument from `/bin/ls` to `/bin/bash`, and this is what the kernel will execute. To mitigate this, Tracee also provide "LSM" (Linux Security Module) based events, for example, the `bprm_check` event which can be reported by tracee and cross-referenced with the reported regular syscall event.
