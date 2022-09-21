# Special: Overriding OS needed files

Tracee supports eBPF CO-RE (Compile Once - Run Everywhere) technology and,
because of that, it might need some information about the Linux OS it is
running at. Tracee, through libbpfgo, must have access to /etc/os-release file
AND either /boot/config-$(uname-r) OR /proc/config.gz files (KernelConfig API
at helpers/kernel_config).

> Note that, despite having this need, tracee will try to execute as CO-RE eBPF
> program in any environment it is executed.

## OS-RELEASE

Tracee will show you collected information about the running Linux OS with the
`--debug` argument:

```
sudo ./dist/tracee-ebpf --debug --trace uid=1000 --trace pid=new --trace event=execve
OSInfo: VERSION_ID: "21.04"
OSInfo: VERSION_CODENAME: hirsute
OSInfo: KERNEL_RELEASE: 5.11.0-31-generic
OSInfo: VERSION: "21.04 (Hirsute Hippo)"
OSInfo: ID: ubuntu
OSInfo: ID_LIKE: debian
OSInfo: PRETTY_NAME: "Ubuntu 21.04"
BTF: bpfenv = false, btfenv = false, vmlinux = true
BPF: using embedded BPF object
unpacked CO:RE bpf object file into memory
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
02:34:43:212623  1000   bash             2787679 2787679 0                execve               pathname: /bin/true, argv: [/bin/true]
```

BUT **os-release file might not exist**:

Because you're running in a distribution that does not have /etc/os-release, or
because you're running inside a container that does not support it, you may
face the following error:

```
sudo ./dist/tracee-ebpf --debug --trace uid=1000 --trace pid=new --trace event=execve
OSInfo: KERNEL_RELEASE: 5.14.0-rc5+
OSInfo: warning: os-release file could not be found
(open /etc/os-release: no such file or directory)
BTF: bpfenv = false, btfenv = false, vmlinux = true
BPF: using embedded BPF object
unpacked CO:RE bpf object file into memory
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
05:37:02:831787  1000   bash             13940   13940   0                execve               pathname: /bin/true, argv: [/bin/true]

End of events stream
Stats: {EventCount:1 ErrorCount:0 LostEvCount:0 LostWrCount:0 LostNtCount:0}
```

!!! Note
    But do note that **tracee-ebpf shall continue working** (informing only the
    KERNEL_RELEASE OSInfo option).

If you need to override the underlaying Linux OS information, because you're
running inside a container that already has /etc/os-release file, for example,
you may create another os-release file and inform tracee-ebpf by using
LIBBPFGO's environment variable `LIBBPFGO_OSRELEASE_FILE`:

```
sudo LIBBPFGO_OSRELEASE_FILE=/etc/os-release.orig ./dist/tracee-ebpf --debug --trace uid=1000 --trace pid=new --trace event=execve
OSInfo: VERSION_CODENAME: impish
OSInfo: ID: ubuntu
OSInfo: ID_LIKE: debian
OSInfo: KERNEL_RELEASE: 5.14.0-rc5+
OSInfo: PRETTY_NAME: "Ubuntu Impish Indri (development branch)"
OSInfo: VERSION_ID: "21.10"
OSInfo: VERSION: "21.10 (Impish Indri)"
BTF: bpfenv = false, btfenv = false, vmlinux = true
BPF: using embedded BPF object
unpacked CO:RE bpf object file into memory
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
05:39:24:100006  1000   bash             14014   14014   0                execve               pathname: /bin/true, argv: [/bin/true]
```

> If you're running tracee inside a docker container, you can simply bind mount
> /etc/os-release from the host as /etc/os-release-host into the guest and
> inform that through the `LIBBPFGO_OSRELEASE_FILE` environment variable.

## KCONFIG

Tracee needs access to kconfig file (/proc/config.gz OR /boot/config-$(uname -r)) in order to:

1. Check if the kernel of your running environment supports needed eBPF features
2. Provide kconfig variables to its eBPF counter-part (so eBPF program take decisions)

!!! Warning
    Tracee **should NOT fail** when it cannot find a kconfig file:

    ```text
    $ sudo ./dist/tracee-ebpf --debug --trace uid=1000 --trace pid=new --trace event=execve
    KConfig: warning: could not check enabled kconfig features
    (could not read /boot/config-5.14.0-rc5+: stat /boot/config-5.14.0-rc5+: no such file or directory)
    OSInfo: KERNEL_RELEASE: 5.14.0-rc5+
    OSInfo: PRETTY_NAME: "Ubuntu Impish Indri (development branch)"
    OSInfo: VERSION_ID: "21.10"
    OSInfo: VERSION: "21.10 (Impish Indri)"
    OSInfo: VERSION_CODENAME: impish
    OSInfo: ID: ubuntu
    OSInfo: ID_LIKE: debian
    BTF: bpfenv = false, btfenv = false, vmlinux = true
    BPF: using embedded BPF object
    unpacked CO:RE bpf object file into memory
    TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
    05:44:18:877838  1000   bash             14089   14089   0                execve               pathname: /bin/true, argv: [/bin/true]
    ```

    but do have in mind it is assuming some things from the host environment and
    its behavior might have inconsistencies.

    If you are running tracee in an environment that does not have a kconfig file
    (nor /proc/config.gz support), it is recommended that you provide the host
    kconfig file location to tracee through the `LIBBPFGO_KCONFIG_FILE` environment
    variable:

```text
sudo LIBBPFGO_KCONFIG_FILE=/boot/config-5.14.0-rc5+.orig ./dist/tracee-ebpf --debug --trace uid=1000 --trace pid=new --trace event=execve
OSInfo: VERSION_CODENAME: impish
OSInfo: ID: ubuntu
OSInfo: ID_LIKE: debian
OSInfo: KERNEL_RELEASE: 5.14.0-rc5+
OSInfo: PRETTY_NAME: "Ubuntu Impish Indri (development branch)"
OSInfo: VERSION_ID: "21.10"
OSInfo: VERSION: "21.10 (Impish Indri)"
BTF: bpfenv = false, btfenv = false, vmlinux = true
BPF: using embedded BPF object
unpacked CO:RE bpf object file into memory
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
05:47:45:245869  1000   bash             14165   14165   0                execve               pathname: /bin/true, argv: [/bin/true]
```

> If you're running tracee inside a docker container, you can simply bind mount
> /boot/config-$(uname -r) from the host as /boot/config-$(uname -r) into the
> guest and inform that through the `LIBBPFGO_KCONFIG_FILE` environment
> variable.

!!! Attention
    In case no kconfig file is found, tracee takes some decisions blindly and
    it may give you unexpected errors. Example:
