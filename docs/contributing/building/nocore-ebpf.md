# Running non CO-RE Tracee

> These instructions are meant to describe how to build tracee's eBPF object
> for your running kernel when it does not support
> [CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/).

## Introduction

!!! Introduction
    As you are probably already aware, **Tracee** consists of:
    
    !!! tracee Tip

        - Userspace agent  
            1. Handles lifecycle of ebpf programs
            1. Receives and detects events from eBPF programs
        - eBPF code
            1. Programs loaded in the kernel for event collection
        - OPA signatures
        - Golang signatures
        - Go-Cel signatures

**Tracee** leverages Linux's eBPF technology, which requires some kernel level
integration, supporting two eBPF integration modes:

1. **CO-RE**: a **portable mode**, which will seamlessly run on all supported
   envs.

    The portable option, also known as CO-RE (compile once, run everywhere),
    requires that your operating system support
    [BTF](https://nakryiko.com/posts/btf-dedup/) (BPF Type Format). Tracee will
    automatically run in CO-RE mode if it detects that the environment supports
    it. The **tracee** binary has a CO-RE eBPF object embedded on it. When
    executed, it loads the CO-RE eBPF object into the kernel and each of its
    object's eBPF programs are executed when triggered by kernel probes, or
    tracepoints, for example.

    This mode requires no intervention or preparation on your side.  You can
    manually detect if your environments supports it by checking if the
    following file exists on your machine: `/sys/kernel/btf/vmlinux`.

2. **non CO-RE**: a **kernel-specific mode**, requiring eBPF object to be built.

    If you want to run Tracee on a host without BTF support, there are 2 options:
    1. to use BTF files from [BTFHUB](https://github.com/aquasecurity/btfhub)
       and provide the TRACEE_BTF_FILE environment variable pointing to the BTF
       file of your running kernel.
    2. to have `../../Makefile` build and install the eBPF object for you
       (instructions in this file). This will depend on having clang and a
       kernel version specific kernel-header package.

## The need for a non CO-RE eBPF object build

Until [recently](https://github.com/aquasecurity/tracee/commit/20549fabefa37b70ca1b8bade8ae39ef0b934942),
**tracee** was capable of building a non CO-RE (portable) eBPF object when
the running kernel did not support BTF, one of the kernel features needed for
eBPF portability among different kernels.

**That now is changed**:

It is the **user responsibility** to have the *non CO-RE eBPF object* correctly
placed in `/tmp/tracee` directory. Tracee will load it, instead of loading the
embedded CO-RE eBPF object, as a last resource if there is no:

1. BTF file available in running kernel (`/sys/kernel/btf/vmlinux`).
1. BTF file pointed by `TRACEE_BTF_FILE` environment variable.
1. BTF file embedded into "tracee" binary ([BTFHUB](https://github.com/aquasecurity/btfhub)).

!!! Note
    Installing the non CO-RE eBPF object in the environment does not mean will
    will run **tracee** with it by default. If your system supports CO-RE
    eBPF objects it will be chosen instead. If your system supports CO-RE eBPF
    but does not contain embedded BTF information, but is support by BTFHUB,
    then the CO-RE eBPF object will be used by default. The only way you can
    make sure the non CO-RE eBPF object is used is by always informing the
    `TRACEE_BPF_FILE=...` environment variable.

**Reasoning behind this change**

With [BTFHUB](https://github.com/aquasecurity/btfhub), it is now possible to
run **tracee** without compiling the eBPF object to each different kernel,
thus removing the automatic builds (although the functionality is still kept
through the Makefile).

## Install the non CO-RE eBPF object

By running:

```console
make clean
make all
make install-bpf-nocore
```

make installs an eBPF object file under `/tmp/tracee` for the current running
kernel. Example:

```console
find /tmp/tracee
```

```text
/tmp/tracee
/tmp/tracee/tracee.bpf.5_4_0-91-generic.v0_6_5-80-ge723a22.o
```

!!! Note
    This example, the Ubuntu Focal kernel **5.4.0-91-generic** supports CO-RE,
    but the kernel does not have embedded BTF information available. In cases
    like this, the user may opt to either use [BTFHUB](https://github.com/aquasecurity/btfhub)
    btf files (with an environment variable TRACEE_BTF_FILE=.../5.4.0-91-generic.btf)
    OR to install the non CO-RE eBPF object and run **tracee** command
    without an env variable.

## Run non CO-RE tracee

If you install the non CO-RE eBPF object and run **tracee** in an environment
that needs it, then the debug output will look like:

```console
sudo ./dist/tracee --log debug
```

```text
{"level":"debug","ts":1670972052.3996286,"msg":"osinfo","VERSION_CODENAME":"focal","KERNEL_RELEASE":"5.4.0-91-generic","ARCH":"x86_64","VERSION":"\"20.04.5 LTS (Focal Fossa)\"","ID":"ubuntu","ID_LIKE":"debian","PRETTY_NAME":"\"Ubuntu 20.04.5 LTS\"","VERSION_ID":"\"20.04\"","pkg":"urfave","file":"urfave.go","line":53}
{"level":"debug","ts":1670972052.3996587,"msg":"RuntimeSockets: failed to register default","socket":"crio","error":"failed to register runtime socket stat /var/run/crio/crio.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670972052.3996656,"msg":"RuntimeSockets: failed to register default","socket":"podman","error":"failed to register runtime socket stat /var/run/podman/podman.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670972052.3998134,"msg":"osinfo","security_lockdown":"none","pkg":"urfave","file":"urfave.go","line":116}
{"level":"debug","ts":1670972052.400891,"msg":"BTF","bpfenv":false,"btfenv":false,"vmlinux":false,"pkg":"initialize","file":"bpfobject.go","line":40}
{"level":"debug","ts":1670972052.4009123,"msg":"BPF: no BTF file was found or provided","pkg":"initialize","file":"bpfobject.go","line":108}
{"level":"debug","ts":1670972052.4009168,"msg":"BPF: trying non CO-RE eBPF","file":"/tmp/tracee/tracee.bpf.5_4_0-91-generic.v0_8_0-rc-2-363-g3e73eeb1.o","pkg":"initialize","file":"bpfobject.go","line":109}
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
...
```

One way of forcing **tracee** to use non CO-RE eBPF object, even in a kernel
that supports CO-RE, is by setting the `TRACEE_BPF_FILE` environment, like this:

```console
sudo TRACEE_BPF_FILE=/tmp/tracee/tracee.bpf.5_4_0-91-generic.v0_8_0-rc-2-363-g3e73eeb1.o ./dist/tracee --log debug -o option:parse-arguments --filter comm=bash --filter follow
```

```text
{"level":"debug","ts":1670972956.7201664,"msg":"osinfo","VERSION_CODENAME":"focal","KERNEL_RELEASE":"5.4.0-91-generic","ARCH":"x86_64","VERSION":"\"20.04.5 LTS (Focal Fossa)\"","ID":"ubuntu","ID_LIKE":"debian","PRETTY_NAME":"\"Ubuntu 20.04.5 LTS\"","VERSION_ID":"\"20.04\"","pkg":"urfave","file":"urfave.go","line":53}
{"level":"debug","ts":1670972956.7202075,"msg":"RuntimeSockets: failed to register default","socket":"crio","error":"failed to register runtime socket stat /var/run/crio/crio.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670972956.7202215,"msg":"RuntimeSockets: failed to register default","socket":"podman","error":"failed to register runtime socket stat /var/run/podman/podman.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670972956.7203856,"msg":"osinfo","security_lockdown":"none","pkg":"urfave","file":"urfave.go","line":116}
{"level":"debug","ts":1670972956.7215962,"msg":"BTF","bpfenv":true,"btfenv":false,"vmlinux":false,"pkg":"initialize","file":"bpfobject.go","line":40}
{"level":"debug","ts":1670972956.7216172,"msg":"BPF: using BPF object from environment","file":"/tmp/tracee/tracee.bpf.5_4_0-91-generic.v0_8_0-rc-2-363-g3e73eeb1.o","pkg":"initialize","file":"bpfobject.go","line":52}
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
...
```

## Use the [building environment](./environment.md)

If you're willing to generate the non CO-RE eBPF object using the `tracee-make`
building environment container, you're able to by doing:

```console
make -f builder/Makefile.tracee-make alpine-prepare
make -f builder/Makefile.tracee-make alpine-shell
```

or

```console
make -f builder/Makefile.tracee-make ubuntu-prepare
make -f builder/Makefile.tracee-make ubuntu-shell
```

and then, **inside** the docker container:

```console
make clean
make tracee
make install-bpf-nocore
sudo ./dist/tracee --log debug
```

```text
{"level":"debug","ts":1670973357.226559,"msg":"osinfo","VERSION_CODENAME":"focal","KERNEL_RELEASE":"5.4.0-91-generic","ARCH":"x86_64","VERSION":"\"20.04.5 LTS (Focal Fossa)\"","ID":"ubuntu","ID_LIKE":"debian","PRETTY_NAME":"\"Ubuntu 20.04.5 LTS\"","VERSION_ID":"\"20.04\"","pkg":"urfave","file":"urfave.go","line":53}
{"level":"debug","ts":1670973357.2265916,"msg":"RuntimeSockets: failed to register default","socket":"containerd","error":"failed to register runtime socket stat /var/run/containerd/containerd.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670973357.2266004,"msg":"RuntimeSockets: failed to register default","socket":"docker","error":"failed to register runtime socket stat /var/run/docker.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670973357.226606,"msg":"RuntimeSockets: failed to register default","socket":"crio","error":"failed to register runtime socket stat /var/run/crio/crio.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670973357.2266123,"msg":"RuntimeSockets: failed to register default","socket":"podman","error":"failed to register runtime socket stat /var/run/podman/podman.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670973357.2268527,"msg":"osinfo","security_lockdown":"none","pkg":"urfave","file":"urfave.go","line":116}
{"level":"warn","ts":1670973357.2268791,"msg":"KConfig: could not check enabled kconfig features","error":"could not read /boot/config-5.4.0-91-generic: stat /boot/config-5.4.0-91-generic: no such file or directory"}
{"level":"warn","ts":1670973357.2268848,"msg":"KConfig: assuming kconfig values, might have unexpected behavior"}
{"level":"debug","ts":1670973357.2268941,"msg":"BTF","bpfenv":false,"btfenv":false,"vmlinux":false,"pkg":"initialize","file":"bpfobject.go","line":40}
{"level":"debug","ts":1670973357.2269084,"msg":"BPF: no BTF file was found or provided","pkg":"initialize","file":"bpfobject.go","line":108}
{"level":"debug","ts":1670973357.2269146,"msg":"BPF: trying non CO-RE eBPF","file":"/tmp/tracee/tracee.bpf.5_4_0-91-generic.v0_8_0-rc-2-363-g3e73eeb1.o","pkg":"initialize","file":"bpfobject.go","line":109}
{"level":"debug","ts":1670973357.3408191,"msg":"Enricher","error":"error registering enricher: unsupported runtime containerd","pkg":"containers","file":"containers.go","line":64}
{"level":"debug","ts":1670973357.3408432,"msg":"Enricher","error":"error registering enricher: unsupported runtime crio","pkg":"containers","file":"containers.go","line":68}
{"level":"debug","ts":1670973357.340847,"msg":"Enricher","error":"error registering enricher: unsupported runtime docker","pkg":"containers","file":"containers.go","line":72}
{"level":"debug","ts":1670973357.561575,"msg":"KConfig: warning: assuming kconfig values, might have unexpected behavior","pkg":"initialization","file":"kconfig.go","line":30}
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
...
```
