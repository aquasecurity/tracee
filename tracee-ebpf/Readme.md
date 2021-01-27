![Tracee Logo](../images/tracee.png)

# Tracee-eBPF: Linux Tracing and Forensics using eBPF

Tracee-eBPF is a lightweight and easy to use tracing tool for Linux, which is focused on security and forensics. It allows you to observe system calls and other system events in real-time, with comprehensive filtering mechanism so you can focus on the events that are relevant to you. Unlike other tracing tools, Tracee, and by extension Tracee-eBPF is a security tool, which is demonstrated by features like capturing forensic artifacts from running applications, tracing non-syscall security events, and producing security insights.

[Check out this quick demo of Tracee-eBPF](https://youtu.be/WTqE2ae257o)

## Getting started

### Prerequisites

- Linux kernel version >= 4.14
- Relevant kernel headers available under conventional location (see [Linux Headers](#Linux-Headers) section for info)
- libc, and the libraries: libelf and zlib
- clang >= 9

Exceptions:

- Tracee supports loading a pre-compiled eBPF file, in which case the kernel headers are required only for the one-time compilation, and not at runtime. See Setup Options for more info.
- When using Tracee's Docker image, all of the aforementioned requirements are built into the image. The only requirement left is the kernel headers or the pre-built eBPF. See Setup Options for more info.

### Quickstart with Docker

```bash
docker run --name tracee --rm --privileged --pid=host -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro -v /tmp/tracee:/tmp/tracee aquasec/tracee:latest
```

> Note: You may need to change the volume mounts for the kernel headers based on your setup. See [Linux Headers](#Linux-Headers) section for info.

This will run Tracee-eBPF with no arguments, which defaults to collecting a useful default set of events from all processes and print them in a table to standard output.

### Getting Tracee-eBPF

You can obtain Tracee-eBPF in any of the following ways:
1. Download from the [GitHub Releases](https://github.com/aquasecurity/tracee/releases) (`tracee.tar.gz`).
2. Use the docker image from Docker Hub: `aquasec/tracee` (includes all the required dependencies).
3. Build the executable from source using `make build`. For that you will need additional development tooling.
4. Build the executable from source in a Docker container which includes all development tooling, using `make build DOCKER=1`.

### Setup options

Tracee-eBPF is made of a userspace executable (`tracee`) that drives the eBPF program, and the eBPF program itself (`tracee.bpf.$kernelversion.$traceeversion.o`). When the `tracee` is started, it will look for the eBPF program in specific places and if not found, it will attempt to build the eBPF program automatically before it starts (you can control this using the `--build-policy` flag).

The eBPF program is searched in the following places (in order):
1. Path specified in `TRACEE_BPF_FILE` environment variable
2. Next to the executable (same directory)
3. `/tmp/tracee`

The easiest way to get started is to just let Tracee build the eBPF program for you automatically, as demonstrated in the previous section [Quickstart with Docker](#quickstart-with-docker).  
Alternatively, you can pre-compile the eBPF program, and provide it to the `tracee` executable. There are some benefits to this approach as you will not need clang and kernel headers at runtime anymore, as well as reduced risk of invoking an external program at runtime.

You can build the eBPF program in the following ways:
1. `make bpf`
2. `make bpf DOCKER=1` to build in a Docker container which includes all development tooling.
3. There is also a handy `make all` (and the `make all DOCKER=1` variant) which builds both the executable and the eBPF program.

Once you have the eBPF program artifact, you can provide it to Tracee in any of the locations mentioned above. In this case, the full Docker image can be replaced by the lighter-weight `aquasec/tracee:slim` image. This image cannot build the eBPF program on its own, and is meant to be used when you have already compiled the eBPF program beforehand.

#### Running in container

Tracee uses a filesystem directory, by default `/tmp/tracee` to capture runtime artifacts, internal components, and other miscellaneous. When running in a container, it's useful to mount this directory in, so that the artifacts are accessible after the container exits. For example, you can add this to the docker run command `-v /tmp/tracee:/tmp/tracee`.

If running in a container, regardless if it's the full or slim image, it's advisable to reuse the eBPF program across runs by mounting it from the host to the container. This way if the container builds the eBPF program it will be persisted on the host, and if the eBPF program already exists on the host, the container will automatically discover it. If you've already mounted the `/tmp/tracee` directory from the host, you're good to go, since Tracee by default will use this location for the eBPF program. You can also mount the eBPF program file individually if it's stored elsewhere (e.g in a shared volume), for example: `-v /path/to/tracee.bpf.1_2_3.4_5_6.o:/some/path/tracee.bpf.1_2_3.4_5_6.o -e TRACEE_BPF_FILE=/some/path`. 

When using the `--capture exec` option, Tracee needs access to the host PID namespace. For Docker, add `--pid=host` to the run command.

If you are building the eBPF program in a container, you'll need to make the kernel headers available in the container. The quickstart example has broader mounts that works in a variety of cases, for demonstration purposes. If you want, you can narrow those mounts down to the specific directory that contains the headers on your setup, for example: `-v /path/to/headers:/myheaders -e KERN_HEADERS=/myheaders`. As mentioned before, a better practice for production is to pre-compile the eBPF program, in which case the kernel headers are not needed at runtime.

#### Permissions

If Tracee is not actually tracing, it doesn't need privileges. For example, just building the eBPF program, or listing the available options, can be done with a regular user.  
For actually tracing, Tracee needs to run with sufficient capabilities: 
- `CAP_SYS_RESOURCE` (to manage eBPF maps limits)
- `CAP_BPF`+`CAP_TRACING` which are available on recent kernels (>=5.8), or `SYS_ADMIN` on older kernels (to load and attach the eBPF programs).

Alternatively, running as `root` or with the `--privileged` flag of Docker, is an easy way to start.

#### Linux Headers

In order to compile the eBPF program, Tracee needs some of the Linux kernel headers. Depending on your Linux distribution, there may be different ways to obtain them.  

- On Ubuntu/Debian/Arch/Manjaro install the `linux-headers` package.
- On CentOS/Fedora install the `kernel-headers` and `kernel-devel` packages.

Normally the files will be installed in `/lib/modules/${kernel_version}/build` which is where Tracee expects them. If you have the headers elsewhere, you can set the `KERN_HEADERS` environment variable with the correct location.

> Note that it's important that the kernel headers match the exact version of kernel you are running. To check the current kernel version, run the command `uname -r`. To install a specific kernel headers version append the version to the package name: `linux-headers-$(uname -r)`.

> Note that more often than not the kernel headers files contains filesystem links to other files in other directories. Therefore, when passing the kernel headers to Tracee docker container, make sure all the necessary directories are mounted. This is why the quickstart example mounts `/usr/src` in addition to `/lib/modules`.

## Using Tracee

Use `tracee --help` to see a full description of available options. Some flags has specific help sections that can be accessed by passing `help` to the flag, for example `--output help`.
This section covers some of the more common options.

### Understanding the output

Here's a sample output of running Tracee-eBPF with no additional arguments:

```
TIME(s)        UID    COMM             PID     TID     RET             EVENT                ARGS
176751.746515  1000   zsh              14726   14726   0               execve               pathname: /usr/bin/ls, argv: [ls]
176751.746772  1000   zsh              14726   14726   0               security_bprm_check  pathname: /usr/bin/ls, dev: 8388610, inode: 777
176751.747044  1000   ls               14726   14726  -2               access               pathname: /etc/ld.so.preload, mode: R_OK
176751.747077  1000   ls               14726   14726   0               security_file_open   pathname: /etc/ld.so.cache, flags: O_RDONLY|O_LARGEFILE, dev: 8388610, inode: 533737
...
```

Each line is a single event collected by Tracee-eBPF, with the following information:

1. TIME - shows the event time relative to system boot time in seconds
2. UID - real user id (in host user namespace) of the calling process
3. COMM - name of the calling process
4. PID - pid of the calling process
5. TID - tid of the calling thread
6. RET - value returned by the function
7. EVENT - identifies the event (e.g. syscall name)
8. ARGS - list of arguments given to the function

### Customizing the output

Tracee-eBPF supports different output formats. For example, to choose json output, use `--output json`.

To tell it to write events to a file instead of stdout, use `--output out-file:/path/to/file`.

There are different ways you can augment the output to add useful information. For example: `--output eot` will add a terminating event to the stream which is useful if feeding the output to another program.

For a full list of output options, run `--output help`.

### Selecting what to trace

Trace output can easily become unwieldy when tracing all of the events from all of the system. Luckily, Tracee has a powerful mechanism to accurately trace just the information that is relevant to you, using the `--trace` flag.
Using the `--trace` you define expressions that tells Tracee-eBPF what you are interested in by means of event metadata, and process metadata. Only events that match this criteria will be traced.

You can filter by most of the visible fields on a Tracee event. For example to trace only events related to user ID 1000, use `--trace uid=1000`.  
You can combine trace expressions into more complex criteria. For example, to trace only events related to user ID 1000, which come from process ID 1234, use `--trace uid=1000 --trace pid=1234`.  

A special `pid` value is `new` which let's you trace all newly created processes (that were created after Tracee started tracing).  
Tracee-eBPF lets you easily trace events that originate in containers using `--trace container` or only new containers (that were created after Tracee started) using `--trace container=new`.

Event metadata can be used in trace expression as well. For example, to trace only `openat` syscalls, use `--trace event:openat`. But you can also filter on a specific argument of the event, e.g `--trace openat.pathname=/bin/ls` which will show only `openat` syscalls that operate on the file `/bin/ls`.

A useful trace mode is the `--trace follow` which, if specified, will trace not only processes that match the given trace expressions, but also their child processes.
For example, the following will trace all the events that originate from zsh shell, including all of the processes that it will spawn: `--trace command=zsh --follow`.

For a complete list of trace options, run `--trace help`.

### Capturing artifacts

Tracee has a unique feature that lets you capture interesting artifacts from running applications, using the `--capture` flag.

All captured artifacts are saved in Tracee's "output directory" which can be configured using `--capture dir:/path/to/dir`.

Tracee can capture the following types of artifacts:

1. Written files: Anytime a file is being written to, the contents of the file will be captured. Written files can be filtered using an optional path prefix.
2. Executed files: Anytime a binary is being executed, the binary file will be captured. If the same binary is executed multiple times, it will be captured just once.
3. Memory files: Anytime a "memory unpacker" is detected, the suspicious memory region will be captured. This is triggered when memory protection changes from Write+Execute to Write.

To use, `--capture exec`, `--capture mem`, and `--capture write` capture executed, memory, and written files respectively. 
To filter written files, add a prefix expression like so: `--capture write=/etc/*`. This will capture anything written blow `/etc/`.

For a complete list of capture options, run `--capture help`.

## Secure tracing

When Tracee-eBPF reads information from user programs it is subject to a race condition where the user program might be able to change the arguments after Tracee has read them. For example, a program invoked `execve("/bin/ls", NULL, 0)`, Tracee picked that up and will report that, then the program changed the first argument from `/bin/ls` to `/bin/bash`, and this is what the kernel will execute. To mitigate this, Tracee also provide "LSM" (Linux Security Module) based events, for example, the `bprm_check` event which can be reported by tracee and cross-referenced with the reported regular syscall event.