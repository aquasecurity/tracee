# Tracing

In some cases, you might want to leverage Tracee's eBPF event collection capabilities directly, without involving the detection engine. This might be useful for debugging/troubleshooting/analysis/research/education. In this case you can use Tracee's eBPF collector component, which will start dumping raw data directly into standard output.

[Watch a quick video demo of Tracee's eBPF tracing capabilities](https://youtu.be/WTqE2ae257o)

## Quickstart

Before you proceed, make sure you follow the [minimum requirements for running Tracee](install/prerequisites.md).

```bash
docker run --name tracee --rm --privileged -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro -v /tmp/tracee:/tmp/tracee -it aquasec/tracee:latest trace
```

Here we are running the same `aquasec/tracee` container, but with the `trace` sub-command, which will start just a raw trace (Tracee-eBPF), without the detection engine (Tracee-Rules). Here's a sample output of running with no additional arguments:

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

## Getting Tracee-eBPF

You can obtain Tracee-eBPF in any of the following ways:
1. Download from the [GitHub Releases](https://github.com/aquasecurity/tracee/releases) (`tracee.tar.gz`).
2. Use the docker image from Docker Hub: `aquasec/tracee` with the `trace` sub-command.
3. Build the executable from source using `make build`. For that you will need additional development tooling.
4. Build the executable from source in a Docker container which includes all development tooling, using `make build DOCKER=1`.

All of the other setup options and considerations listed under Tracee's Installation section applies to Tracee-eBPF as well.
