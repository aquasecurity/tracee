# Prerequisites for running Tracee

Tracee is heavily dependent on Linux and does not support any other operating system.

## Kernel version

A longterm supported kernel: 5.4, 5.10, 5.15, 5.18, 6.1, 6.2. Check [kernel.org](https://kernel.org) for current supported kernels.
In addition to upstream kernels, most distributions long-term supported kernels are supported as well, including CentOS8 4.18 kernel.

## BTF

In order to properly instrument the kernel, Tracee needs low-level type information about the running kernel. Most modern Linux distributions ship with the [BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html) feature that exposes this information.
To test if your linux has BFT enabled, look for a file under `/sys/kernel/btf/vmlinux`. If you don't have BTF, you might need to upgrade to a newer OS version, or contact your OS provider.

## Kernel symbols

Certain Tracee events require access to the Kernel Symbols Table, a feature
present in many Linux distributions.

A running Linux kernel might lack the `/proc/kallsyms` file due to:

**Kernel Configuration**: If compiled without `CONFIG_KALLSYMS`, the kernel
won't have this file. This option enables the kernel symbol table, used mainly
for debugging.

**Security Protocols**: Some systems might hide kernel symbols to prevent
potential exploits. The `/proc/kallsyms` file could appear incomplete or even
empty to non-root users. The `CONFIG_KALLSYMS_ALL` option ensures all symbols
are visible.

The Linux kernel also offers a setting, `/proc/sys/kernel/kptr_restrict`, to
control kernel symbol visibility:

- **0**: No restrictions.
- **1**: Hide from non-privileged users.
- **2**: Hide from all users.

To check support, see if `/proc/kallsyms` exists. If absent, contact your OS
provider. Alternatively, you can disable the following events which depends on
kallsyms:

- dirty_pipe_splice (detects dirty pipe vulnerability - CVE-2022-0847)
- hooked_syscall (detects system call interception technique)
- hidden_kernel_module (detects hidden kernel modules technique)
- hooked_proc_fops (detects procfs file operations interception technique)
- print_net_seq_ops (related hooked_seq_ops event)
- hooked_seq_ops (detects network packets interception technique)
- print_mem_dump (allows memory dumping from symbols to signatures can use)

## OS information

In order to properly instrument the kernel, Tracee is probing the running OS and kernel to detect available capabilities.
For OS information please make sure the file `/etc/os-release` is available.
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
