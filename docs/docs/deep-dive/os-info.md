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
`--log debug` argument:

```console
sudo ./dist/tracee --log debug --scope uid=1000 --scope pid=new --events execve
```

```text
{"level":"debug","ts":1670976393.7308447,"msg":"osinfo","ARCH":"x86_64","PRETTY_NAME":"\"Manjaro Linux\"","ID":"manjaro","ID_LIKE":"arch","BUILD_ID":"rolling","KERNEL_RELEASE":"5.15.81-1-MANJARO","pkg":"urfave","file":"urfave.go","line":53}
{"level":"debug","ts":1670976393.73088,"msg":"RuntimeSockets: failed to register default","socket":"containerd","error":"failed to register runtime socket stat /var/run/containerd/containerd.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670976393.730894,"msg":"RuntimeSockets: failed to register default","socket":"crio","error":"failed to register runtime socket stat /var/run/crio/crio.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670976393.7309017,"msg":"RuntimeSockets: failed to register default","socket":"podman","error":"failed to register runtime socket stat /var/run/podman/podman.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670976393.7310617,"msg":"osinfo","security_lockdown":"none","pkg":"urfave","file":"urfave.go","line":116}
{"level":"debug","ts":1670976393.733237,"msg":"BTF","bpfenv":false,"btfenv":false,"vmlinux":true,"pkg":"initialize","file":"bpfobject.go","line":40}
{"level":"debug","ts":1670976393.7332687,"msg":"BPF: using embedded BPF object","pkg":"initialize","file":"bpfobject.go","line":69}
{"level":"debug","ts":1670976393.7355402,"msg":"unpacked CO:RE bpf object file into memory","pkg":"initialize","file":"bpfobject.go","line":144}
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
21:06:35:386730  1000   gio-launch-desk  743960  743960  0                execve               pathname: /home/gg/.local/bin/gnome-terminal, argv: [gnome-terminal]
...
```

BUT **os-release file might not exist**:

Because you're running in a distribution that does not have /etc/os-release, or
because you're running inside a container that does not support it, you may
face the following error:

```console
sudo ./dist/tracee --log debug --scope uid=1000 --scope pid=new --events execve
```

```text
{"level":"debug","ts":1670976530.5685039,"msg":"osinfo", "warning: os-release file could not be found","error","open /etc/os-release: no such file or directory","pkg":"urfave","file":"urfave.go","line":33}
...
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
...

End of events stream
Stats: {EventCount:1 ErrorCount:0 LostEvCount:0 LostWrCount:0 LostNtCount:0}
```

!!! Note
    But do note that **tracee shall continue working** (informing only the
    KERNEL_RELEASE OSInfo option).

If you need to override the underlying Linux OS information, because you're
running inside a container that already has /etc/os-release file, for example,
you may create another os-release file and inform tracee by using
LIBBPFGO's environment variable `LIBBPFGO_OSRELEASE_FILE`:

```console
sudo LIBBPFGO_OSRELEASE_FILE=/etc/os-release.orig ./dist/tracee --scope uid=1000 --scope pid=new --events execve
```

> If you're running tracee inside a docker container, you can simply bind mount
> `/etc/os-release` from the host as `/etc/os-release-host` into the guest.

## KCONFIG

Tracee needs access to kconfig file (/proc/config.gz OR /boot/config-$(uname -r)) in order to:

1. Check if the kernel of your running environment supports needed eBPF features
2. Provide kconfig variables to its eBPF counter-part (so eBPF program take decisions)

!!! Warning
    Tracee **should NOT fail** when it cannot find a kconfig file or needed options:
    
    - **missing kconfig file**

    ```console
    sudo ./dist/tracee --log debug --scope uid=1000 --scope pid=new --events execve
    ```

    ```json
    {"level":"debug","ts":1670976875.7735798,"msg":"osinfo","VERSION":"\"20.04.5 LTS (Focal Fossa)\"","ID":"ubuntu","ID_LIKE":"debian","PRETTY_NAME":"\"Ubuntu 20.04.5 LTS\"","VERSION_ID":"\"20.04\"","VERSION_CODENAME":"focal","KERNEL_RELEASE":"5.4.0-91-generic","ARCH":"x86_64","pkg":"urfave","file":"urfave.go","line":53}
    ...
    {"level":"warn","ts":1670976875.7762284,"msg":"KConfig: could not check enabled kconfig features","error":"could not read /boot/config-5.4.0-91-generic: stat /boot/config-5.4.0-91-generic: no such file or directory"}
    {"level":"warn","ts":1670976875.7762842,"msg":"KConfig: assuming kconfig values, might have unexpected behavior"}
    ...
    {"level":"debug","ts":1670976876.0801573,"msg":"KConfig: warning: assuming kconfig values, might have unexpected behavior","pkg":"initialization","file":"kconfig.go","line":30}
    TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
    ...
    ```

    - **missing kconfig options**

    ```json
    {"level":"warn","ts":1698759121.4432194,"msg":"KConfig: could not detect kconfig options","options":[...]}
    ```
    
    But do have in mind it is assuming some things from the host environment and
    its behavior might have inconsistencies.
    
    If you are running tracee in an environment that does not have a kconfig file
    (nor /proc/config.gz support), it is recommended that you provide the host
    kconfig file location to tracee through the `LIBBPFGO_KCONFIG_FILE` environment
    variable:

```console
sudo LIBBPFGO_KCONFIG_FILE=/boot/config-other -E ./dist/tracee --log debug --scope uid=1000 --scope pid=new --events execve
```

```text
{"level":"debug","ts":1670979362.3586345,"msg":"osinfo","VERSION_ID":"\"20.04\"","VERSION_CODENAME":"focal","KERNEL_RELEASE":"5.4.0-91-generic","ARCH":"x86_64","VERSION":"\"20.04.5 LTS (Focal Fossa)\"","ID":"ubuntu","ID_LIKE":"debian","PRETTY_NAME":"\"Ubuntu 20.04.5 LTS\"","pkg":"urfave","file":"urfave.go","line":53}
{"level":"debug","ts":1670979362.358663,"msg":"RuntimeSockets: failed to register default","socket":"containerd","error":"failed to register runtime socket stat /var/run/containerd/containerd.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670979362.3586702,"msg":"RuntimeSockets: failed to register default","socket":"docker","error":"failed to register runtime socket stat /var/run/docker.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670979362.3586755,"msg":"RuntimeSockets: failed to register default","socket":"crio","error":"failed to register runtime socket stat /var/run/crio/crio.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670979362.3586833,"msg":"RuntimeSockets: failed to register default","socket":"podman","error":"failed to register runtime socket stat /var/run/podman/podman.sock: no such file or directory","pkg":"flags","file":"containers.go","line":45}
{"level":"debug","ts":1670979362.3588264,"msg":"osinfo","security_lockdown":"none","pkg":"urfave","file":"urfave.go","line":116}
{"level":"debug","ts":1670979362.3639433,"msg":"BTF","bpfenv":false,"btfenv":false,"vmlinux":false,"pkg":"initialize","file":"bpfobject.go","line":40}
{"level":"debug","ts":1670979362.363965,"msg":"BPF: no BTF file was found or provided","pkg":"initialize","file":"bpfobject.go","line":108}
{"level":"debug","ts":1670979362.3639715,"msg":"BPF: trying non CO-RE eBPF","file":"/tmp/tracee/tracee.bpf.5_4_0-91-generic.v0_8_0-rc-2-365-g0bac8f68.o","pkg":"initialize","file":"bpfobject.go","line":109}
{"level":"debug","ts":1670979362.4866858,"msg":"Enricher","error":"error registering enricher: unsupported runtime containerd","pkg":"containers","file":"containers.go","line":64}
{"level":"debug","ts":1670979362.486713,"msg":"Enricher","error":"error registering enricher: unsupported runtime crio","pkg":"containers","file":"containers.go","line":68}
{"level":"debug","ts":1670979362.486717,"msg":"Enricher","error":"error registering enricher: unsupported runtime docker","pkg":"containers","file":"containers.go","line":72}
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
...
```

> If you're running tracee inside a docker container, you can simply bind mount
> /boot/config-$(uname -r) from the host as /boot/config-$(uname -r) into the
> guest and inform that through the `LIBBPFGO_KCONFIG_FILE` environment
> variable.

!!! Attention
    In case no kconfig file is found, tracee takes some decisions blindly and
    it may give you unexpected errors.
