# Prerequisites for running Tracee

A longterm supported kernel: 5.4, 5.10, 5.15, 5.18, 6.1, 6.2. Check
[kernel.org](https://kernel.org) for current supported kernels.

!!! Note
    Most distributions long-term supported kernels are supported as well,
    including CentOS8 4.18 kernel.

- For **tracee:{{ git.tag }}** docker image, you should have one of the two:

    1. A kernel that has `/sys/kernel/btf/vmlinux` file available
    2. A kernel supported through [BTFHUB]
    > see [libbpf CO-RE documentation] for more info

## Permissions

For using the eBPF Linux subsystem, Tracee needs to run with sufficient
capabilities:

* Manage eBPF maps limits (`CAP_SYS_RESOURCE`)
* Load and Attach eBPF programs:
    1. `CAP_BPF`+`CAP_PERFMON` for recent kernels (>=5.8) where the kernel perf paranoid value in `/proc/sys/kernel/perf_event_paranoid` is equal to 2 or less
    2. or `CAP_SYS_ADMIN` otherwise
* `CAP_SYS_PTRACE` (to collect information about processes)
* `CAP_NET_ADMIN` (to use tc for packets capture)
* `CAP_SETPCAP` (if given - used to reduce bounding set capabilities)
* `CAP_SYSLOG` (to access kernel symbols through /proc/kallsyms)
* On some environments (e.g. Ubuntu) `CAP_IPC_LOCK` might be required as well.
* On cgroup v1 environments, `CAP_SYS_ADMIN` is recommended if running from a
  container in order to allow tracee to mount the cpuset cgroup controller.

> Alternatively, you may [bypass the capabilities dropping feature](../../docs/deep-dive/dropping-capabilities.md) if facing any issue.

[libbpf CO-RE documentation]: https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere
[BTFHUB]: https://github.com/aquasecurity/btfhub-archive
