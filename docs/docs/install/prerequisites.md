# Prerequisites for running Tracee

Tracee is heavily dependent on Linux and does not support any other operating system.

## Kernel version

A longterm supported kernel: 5.4, 5.10, 5.15, 5.18, 6.1, 6.2. Check [kernel.org](https://kernel.org) for current supported kernels.  
In addition to upstream kernels, most distributions long-term supported kernels are supported as well, including CentOS8 4.18 kernel.

## BTF

In order to properly instrument the kernel, Tracee needs low-level type information about the running kernel. Most modern Linux distributions ship with the [BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html) feature that exposes this information.  
To test if your linux has BFT enabled, look for a file under `/sys/kernel/btf/vmlinux`. If you don't have BTF, you might need to upgrade to a newer OS version, or contact your OS provider.

## Kernel symbols

Some Tracee events needs access to the Kernel Symbols Table. Most Linux distributions ship with this feature enabled.
To test if your Linux supports it, look for a file under `/proc/kallsyms`. If your don't have it, you might contact your OS provider.

Alternatively you can disable the following events which depends on kallsyms:

- TODO

## OS information

In order to properly instrument the kernel, Tracee is probing the running OS and kernel to detect available capabilities.
For Os information please make sure the file `/etc/os-release` is available.
For Kernel information please make sure on of the files `/boot/config-$(uname-r)` OR `/proc/config.gz` is available.

For more information and advanced configuration of OS info files please see [here](../deep-dive/os-info.md)

## Process capabilities

In order to properly instrument the kernel, Tracee needs sufficient capabilities. The easiest way is run Tracee as "privileged" or "root".  
If you want to run Tracee with "least privileges", here are the required capabilities and justifications:

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

For more information and advanced configuration of process capabilities please see [here](../deep-dive/dropping-capabilities.md)

## Processor architecture

Tracee supports x86 and arm64 processors.
