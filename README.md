# Tracee - System tracing using eBPF

Tracee is a lightweight and easy to use system tracing tool. It allows you to observe system calls and other system events in real time.

Tracee CLI was originally written in Python, but was since ported to Go. Currently both versions are still available in the repo, but future development will be in Go and the Python version will eventually be deprecated and removed.

## Getting started

### Prerequisites
To run, Tracee requires the following:
* Linux kernel version > 4.14
* Kernel headers
* C standard library (currently tested with glibc)
* [BCC](https://github.com/iovisor/bcc)

### Released artifacts
Currently we don't yet have a release process for Tracee. You can build Tracee from source using `make build` or use the Docker image: `aquasec/tracee:latest` from Docker Hub.

### Quickstart
Following is a quick start tutorial on Ubuntu VM with Docker.
Ubuntu is a convenient image which includes all of the host requirements (kernel, headers, glibc). BCC is included in the tracee container image.
To run Tracee using docker:

```bash
docker run --name tracee --rm --privileged -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro aquasec/tracee:latest
```

This will run Tracee with no arguments which will collect all events from all newly created processes and print them as a table to the standard output.

### Understanding the output

Each line is a single event collected by Tracee, with the following information:

1. TIME - shows the event time relative to system boot time in seconds
2. UTS_NAME - uts namespace name. As there is no container id object in the kernel, and docker/k8s will usually set this to the container id, we use this field to distinguish between containers.
3. MNT_NS - mount namespace inode number.
4. PID_NS - pid namespace inode number. In order to know if there are different containers in the same pid namespace (e.g. in a k8s pod), it is possible to check this value
5. UID - real user id (in host user namespace) of the calling process
6. EVENT - identifies the event (e.g. syscall name)
7. COMM - name of the calling process
8. PID - pid of the calling process
9. TID - tid of the calling thread
10. PPID - parent pid of the calling process
11. RET - value returned by the function
12. ARGS - list of arguments given to the function

### Configuration flags

Use `--help` to see a full description of all options.

## Secure tracing

When Tracee reads information from user programs it is subject to a rare condition where the user program might be able to change the arguments after Tracee has read them. For example, a program invoked `execve("/bin/ls", NULL, 0)`, Tracee picked that up and will report that, then the program changed the first argument from `/bin/ls` to `/bin/bash`, and this is what the kernel will execute. To mitigate this, Tracee also provide "LSM" (Linux Security Module) based events, for example the `bprm_check` event which can reported by tracee and cross-referenced with the reported regular syscall event.