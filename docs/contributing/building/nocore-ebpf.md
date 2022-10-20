# Running non CO-RE Tracee

> These instructions are meant to describe how to build tracee's eBPF object
> for your running kernel when it does not support
> [CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/).

## Introduction

!!! Introduction
    As you are probably already aware, **Tracee** consists of:
    
    !!! tracee-ebpf Tip

        - Userspace agent  
            1. Handles lifecycle of ebpf programs  
            1. Receives events from eBPF programs  
        - eBPF code  
            1. Programs loaded in the kernel for event collection
    
    !!! tracee-rules Tip

        - OPA signatures
        - Golang signatures
        - Go-Cel signatures (tech-preview)

**tracee-ebpf** leverages Linux's eBPF technology, which requires some kernel
level integration. **Tracee** supports two eBPF integration modes:

1. **CO-RE**: a **portable mode**, which will seamlessly run on all supported
   envs.

    The portable option, also known as CO-RE (compile once, run everywhere),
    requires that your operating system support
    [BTF](https://nakryiko.com/posts/btf-dedup/) (BPF Type Format). Tracee will
    automatically run in CO-RE mode if it detects that the environment supports
    it. The **tracee-ebpf** binary has a CO-RE eBPF object embedded on it. When
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
**tracee-ebpf** was capable of building a non CO-RE (portable) eBPF object when
the running kernel did not support BTF, one of the kernel features needed for
eBPF portability among different kernels.

**That now is changed**:

It is the **user responsibility** to have the *non CO-RE eBPF object* correctly
placed in `/tmp/tracee` directory. Tracee will load it, instead of loading the
embedded CO-RE eBPF object, as a last resource if there is no:

1. BTF file available in running kernel (`/sys/kernel/btf/vmlinux`).
1. BTF file pointed by `TRACEE_BTF_FILE` environment variable.
1. BTF file embedded into "tracee-ebpf" binary ([BTFHUB](https://github.com/aquasecurity/btfhub)).

!!! Note
    Installing the non CO-RE eBPF object in the environment does not mean will
    will run **tracee-ebpf** with it by default. If your system supports CO-RE
    eBPF objects it will be chosen instead. If your system supports CO-RE eBPF
    but does not contain embedded BTF information, but is support by BTFHUB,
    then the CO-RE eBPF object will be used by default. The only way you can
    make sure the non CO-RE eBPF object is used is by always informing the
    `TRACEE_BPF_FILE=...` environment variable.

**Reasoning behind this change**

With [BTFHUB](https://github.com/aquasecurity/btfhub), it is now possible to
run **tracee-ebpf** without compiling the eBPF object to each different kernel,
thus removing the automatic builds (although the functionality is still kept
through the Makefile).

## Install the non CO-RE eBPF object

By running:

```text
$ make clean
$ make all
$ make install-bpf-nocore
```

make installs an eBPF object file under `/tmp/tracee` for the current running
kernel. Example:

```text
$ find /tmp/tracee
/tmp/tracee
/tmp/tracee/tracee.bpf.5_4_0-91-generic.v0_6_5-80-ge723a22.o
```

!!! Note
    This example, the Ubuntu Focal kernel **5.4.0-91-generic** supports CO-RE,
    but the kernel does not have embedded BTF information available. In cases
    like this, the user may opt to either use [BTFHUB](https://github.com/aquasecurity/btfhub)
    btf files (with an environment variable TRACEE_BTF_FILE=.../5.4.0-91-generic.btf)
    OR to install the non CO-RE eBPF object and run **tracee-ebpf** command
    without an env variable.

## Run non CO-RE tracee-ebpf

If you install the non CO-RE eBPF object and run **tracee-ebpf** in an
environment that needs it, then the debug output will look like:

```text
$ sudo ./dist/tracee-ebpf --debug

OSInfo: ARCH: x86_64
OSInfo: VERSION: "20.04.3 LTS (Focal Fossa)"
OSInfo: ID: ubuntu
OSInfo: ID_LIKE: debian
OSInfo: PRETTY_NAME: "Ubuntu 20.04.3 LTS"
OSInfo: VERSION_ID: "20.04"
OSInfo: VERSION_CODENAME: focal
OSInfo: KERNEL_RELEASE: 5.8.0-63-generic
BTF: bpfenv = false, btfenv = false, vmlinux = false
BPF: no BTF file was found or provided, trying non CO-RE eBPF at
     /tmp/tracee/tracee.bpf.5_8_0-63-generic.v0_6_5-20-g3353501.o
```

One way of forcing **tracee-ebpf** to use non CO-RE eBPF object, even in a kernel
that supports CO-RE, is by setting the `TRACEE_BPF_FILE` environment, like this:

```
$ sudo TRACEE_BPF_FILE=/tmp/tracee/tracee.bpf.5_4_0-91-generic.v0_6_5-80-ge723a22.o ./dist/tracee-ebpf --debug -o option:parse-arguments --trace comm=bash --trace follow
OSInfo: PRETTY_NAME: "Ubuntu 20.04.3 LTS"
OSInfo: VERSION_ID: "20.04"
OSInfo: VERSION_CODENAME: focal
OSInfo: KERNEL_RELEASE: 5.4.0-91-generic
OSInfo: ARCH: x86_64
OSInfo: VERSION: "20.04.3 LTS (Focal Fossa)"
OSInfo: ID: ubuntu
OSInfo: ID_LIKE: debian
BTF: bpfenv = true, btfenv = false, vmlinux = false
BPF: using BPF object from environment: /tmp/tracee/tracee.bpf.5_4_0-91-generic.v0_6_5-80-ge723a22.o
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
...
```

## Use the [building environment](./environment.md)

If you're willing to generate the non CO-RE eBPF object using the `tracee-make`
building environment container, you're able to by doing:

```text
$ make -f builder/Makefile.tracee-make alpine-prepare
$ make -f builder/Makefile.tracee-make alpine-shell
```
or
```text
$ make -f builder/Makefile.tracee-make ubuntu-prepare
$ make -f builder/Makefile.tracee-make ubuntu-shell
```

and then, inside the docker container:

```text
tracee@f65bab137305[/tracee]$ make clean
tracee@f65bab137305[/tracee]$ make tracee-ebpf
tracee@f65bab137305[/tracee]$ make install-bpf-nocore

tracee@f65bab137305[/tracee]$ sudo ./dist/tracee-ebpf --debug
KConfig: warning: could not check enabled kconfig features
(could not read /boot/config-5.8.0-63-generic: ...)
KConfig: warning: assuming kconfig values, might have unexpected behavior
OSInfo: KERNEL_RELEASE: 5.8.0-63-generic
OSInfo: ARCH: x86_64
OSInfo: VERSION: "21.04 (Hirsute Hippo)"
OSInfo: ID: ubuntu
OSInfo: ID_LIKE: debian
OSInfo: PRETTY_NAME: "Ubuntu 21.04"
OSInfo: VERSION_ID: "21.04"
OSInfo: VERSION_CODENAME: hirsute
BTF: bpfenv = false, btfenv = false, vmlinux = false
BPF: no BTF file was found or provided
BPF: trying non CO-RE eBPF at /tmp/tracee/tracee.bpf.5_8_0-63-generic.v0_6_5-20-g0b921b1.o
KConfig: warning: assuming kconfig values, might have unexpected behavior
TIME             UID    COMM             PID     TID     RET ...
```
