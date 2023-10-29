# Prerequisites for running Tracee

Tracee is heavily dependent on Linux and does not support any other operating system.

<!--
every section should roughly cover:
1. what is this prereq
2. why is it needed
3. how to test if I'm compliant
4. link for details and help
-->

## Kernel version

To run Tracee a modern longterm supported kernel is needed: 5.4, 5.10, 5.15, 5.18, 6.1, 6.2.

You can check [kernel.org](https://kernel.org) for current supported kernels.  
In addition to upstream kernels, most distributions long-term supported kernels are supported as well, including CentOS8 4.18 kernel.

## BTF

Tracee needs low-level type information about the running kernel. Most modern Linux distributions ship with the [BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html) feature that exposes this information.  

To test if this feature is enabled in your environment, check if `/sys/kernel/btf/vmlinux` exists. If absent, you might need to upgrade to a newer OS version, or contact your OS provider.

## Kernel symbols

Certain Tracee events require access to the Kernel Symbols Table, a feature present in many Linux distributions.

To test if this feature is enabled in your environment, check if `/proc/kallsyms` exists. If absent, contact your OS provider. 

Alternatively, you can disable the following events which depends on kallsyms:

- `dirty_pipe_splice` (detects dirty pipe vulnerability - CVE-2022-0847)
- `hooked_syscall` (detects system call interception technique)
- `hidden_kernel_module` (detects hidden kernel modules technique)
- `hooked_proc_fops` (detects procfs file operations interception technique)
- `print_net_seq_ops` (related hooked_seq_ops event)
- `hooked_seq_ops` (detects network packets interception technique)
- `print_mem_dump` (allows memory dumping from symbols to signatures can use)

For more information and help about kernel symbols, please see [here](../deep-dive/ksyms.md).

## OS information

Tracee will try to probe the running OS and kernel to detect available capabilities. For this, it needs access to some standard informative files:

- For OS information please make sure the file `/etc/os-release` is available.
- For Kernel information please make sure on of the files `/boot/config-$(uname-r)` OR `/proc/config.gz` is available.

For more information and help about OS info files, please see [here](../deep-dive/os-info.md).

## Process capabilities

Tracee needs non-trivial capabilities to instrument the kernel. The easiest way is run Tracee as "privileged" or "root".  

If you want to run Tracee with "least privileges", here are the required capabilities and justifications:

- Manage eBPF maps limits (`CAP_SYS_RESOURCE`)
- Load and Attach eBPF programs:
    - `CAP_BPF`+`CAP_PERFMON` for recent kernels (>=5.8) where the kernel perf paranoid value in `/proc/sys/kernel/perf_event_paranoid` is equal to 2 or less
    - or `CAP_SYS_ADMIN` otherwise
- `CAP_SYS_PTRACE` (to collect information about processes)
- `CAP_NET_ADMIN` (to use tc for packets capture)
- `CAP_SETPCAP` (if given - used to reduce bounding set capabilities)
- `CAP_SYSLOG` (to access kernel symbols through /proc/kallsyms)
- On some environments (e.g. Ubuntu) `CAP_IPC_LOCK` might be required as well.
- On cgroup v1 environments, `CAP_SYS_ADMIN` is recommended if running from a container in order to allow tracee to mount the cpuset cgroup controller.

For more information and help about process capabilities, please see [here](../deep-dive/dropping-capabilities.md).

## Processor architecture

Tracee supports x86 and arm64 processors.
