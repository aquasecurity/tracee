# Getting Started with Tracing

!!! Note
    This entire section is about running **tracee-ebpf** only, without piping
    events to **tracee-rules**.

In some cases, you might want to leverage Tracee event collection capabilities
only, without involving the [detection engine]. You may, or may not, choose to
[capture artifacts] while tracing.

[detection engine]: ../detecting/index.md
[capture artifacts]: ../capturing/index.md

This might be useful for:

1. **debugging**
1. **troubleshooting**
1. **analysing executions**
1. **security research**
1. **education**

In this case you can use Tracee's eBPF collector component (**tracee-ebpf**),
which will start dumping raw data directly into standard output.

[Watch a quick video demo of Tracee's eBPF tracing capabilities](https://youtu.be/WTqE2ae257o)

## Using Tracee-eBPF

Before you proceed, make sure you follow the [prerequisites].

[prerequisites]:../installing/prerequisites.md

```text
$ docker run \
    --name tracee --rm -it \
    --pid=host --cgroupns=host --privileged \
    -v /etc/os-release:/etc/os-release-host:ro \
    -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
    aquasec/tracee:{{ git.tag[1:] }} \
    trace
```

Here, we are running the `aquasec/tracee` container, but with the
`trace` sub-command, which will start just a raw
trace (Tracee-eBPF), without the detection engine **tracee-rules**. Here's a
sample output of running with no additional arguments:

```text
TIME(s)        UID    COMM             PID     TID     RET             EVENT                ARGS
176751.746515  1000   zsh              14726   14726   0               execve               pathname: /usr/bin/ls, argv: [ls]
176751.746772  1000   zsh              14726   14726   0               security_bprm_check  pathname: /usr/bin/ls, dev: 8388610, inode: 777
176751.747044  1000   ls               14726   14726  -2               access               pathname: /etc/ld.so.preload, mode: R_OK
176751.747077  1000   ls               14726   14726   0               security_file_open   pathname: /etc/ld.so.cache, flags: O_RDONLY|O_LARGEFILE, dev: 8388610, inode: 533737
...

```

!!! Note
    There are 2 ways to enable tracing only:  
    1. To export a TRACEE_EBPF_ONLY=1 env variable to docker.  
    2. To provide a `trace` 1st argument to docker container.  

Each line is a single event collected by Tracee-eBPF, with the following
information:

1. **TIME**  
   event time relative to system boot time in seconds
2. **UID**  
   real user id of the calling process (in host userns)
3. **COMM**  
   name of the calling process
4. **PID**  
   pid of the calling process
5. **TID**  
   tid of the calling thread
6. **RET**  
   value returned by the function
7. **EVENT**  
   identifies the event (e.g. syscall name)
8. **ARGS**  
   list of arguments given to the function

!!! Note
    Use the `--help` flag to see a full description of available options. Some
    flags have specific help sections that can be accessed by passing `help` to
    the flag, for example `--output help`. This section covers some of the more
    common options.

> Check the existing [output options](./output-options.md) for other output options.
> Check the existing [output format](./output-formats.md) for other output formats.

> Follow [getting tracee](../installing/getting.md) in order to get tracee-ebpf.
