# Prerequisites for running Tracee

A long-term supported kernel: 5.4, 5.10, 5.15, 5.18, 5.19. Check
[kernel.org](https://kernel.org) for current supported kernels.

!!! Note
    Most distributions long-term supported kernels are supported as well,
    including CentOS8 4.18 kernel.

1. For **tracee:{{ git.tag }}** docker image, you should have one of the two:

    1. A kernel that has `/sys/kernel/btf/vmlinux` file available
    2. A kernel supported through [BTFHUB]
    > see [libbpf CO-RE documentation] for more info

2. For **tracee:full** docker image:

    1. **kernel readers** (most distros provide packages)
    2. **clang** (12, 13 or 14)
    3. **golang** (1.19)
    4. **libelf** and **libelf-dev** (or elfutils-libelf and elfutils-libelf-devel)
    5. **zlib1g** and **lib1g-dev** (or zlib and zlib-devel)

## Permissions

For using the eBPF Linux subsystem, Tracee needs to run with sufficient
capabilities:

* Manage eBPF maps limits (`CAP_SYS_RESOURCE`)
* Load and Attach eBPF programs:
    1. `CAP_BPF`+`CAP_PERFMON` for recent kernels (>=5.8) where the kernel perf paranoid value in `/proc/sys/kernel/perf_event_paranoid` is equal to 2 or less
    2. or `CAP_SYS_ADMIN` otherwise
* `CAP_SYS_PTRACE` (to collect information about processes upon startup)
* `CAP_NET_ADMIN` (to use tc for packets capture)
* `CAP_SETPCAP` (if given - used to reduce bounding set capabilities)
* `CAP_SYSLOG` (to access kernel symbols through /proc/kallsyms)
* On some environments (e.g. Ubuntu) `CAP_IPC_LOCK` might be required as well.
* On cgroup v1 environments, `CAP_SYS_ADMIN` is recommended if running from a
  container in order to allow tracee to mount the cpuset cgroup controller.

> Alternatively, run as `root` or with **Docker** `--pid=host --cgroupns=host --privileged` flags.

[libbpf CO-RE documentation]: https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere
[BTFHUB]: https://github.com/aquasecurity/btfhub-archive
