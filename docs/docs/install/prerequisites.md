# Prerequisites for running Tracee

Tracee is heavily dependent on Linux and does not support any other operating system.

<!--
every section should roughly cover:
1. what is this prereq
2. why is it needed
3. how to test if I'm compliant
4. link for details and help
-->

## Distributions and Linux Flavors

- List of supported environments:
  - With BTFHUB (check BTF session below):
    - Centos 8 (kernel < 4.18.0-193.el8)
    - Debian 10 (buster) with v5.10 kernels
    - Oracle Linux 7 and 8 with v5.4 kernels
    - Red Hat 8 (kernel <= 4.18.0-147.57.1)
    - SuSe 15.3 (kernel < 5.3.18-150300.59.90)
  - Regular Build:
    - Amazon Linux 2
    - Centos 8 and newer
    - Debian 11 (bullseye) and newer
    - Fedora 38 and newer
    - Oracle Linux 7, 8 (v5.4 kernels, some might need btfhub) and newer
    - Red Hat 8 (newer v4.18 kernels) and newer
    - SuSe 15.3 (newer kernels) and newer
    - Possibly other distributions with recent kernels.
  - Cloud Environments:
    - Amazon EKS
    - Azure AKS
    - GKE (Google Kubernetes Engine): 5.4, 5.10, 5.15 and newer
    - Minikube, Microk8s and other development environments

> This list is based on capabilities those versions provide and not necessarily
in tracee having all its features tested on each of them. Please provide
feedback if you face any issues in one of those environments.

## Kernel version

To run Tracee a modern longterm supported kernel is needed: 5.4, 5.10, 5.15, 6.2, 6.5  

You can check [kernel.org](https://kernel.org) for current supported kernels. In
addition to upstream kernels, most distributions long-term supported kernels are
supported as well, including CentOS8 4.18 kernel.

## BTF

Tracee needs low-level type information about the running kernel. Most modern
Linux distributions ship with the [BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html)
feature that exposes this information.  

To test if this feature is enabled in your environment, check if
`/sys/kernel/btf/vmlinux` exists. If absent, you might need to upgrade to a
newer OS version, or contact your OS provider.

## Kernel symbols

Certain Tracee events require access to the Kernel Symbols Table, a feature
present in many Linux distributions.

To test if this feature is enabled in your environment, check if
`/proc/kallsyms` exists. If absent, contact your OS provider.

Alternatively, you can disable the following events which depends on kallsyms:

- `dirty_pipe_splice` (detects dirty pipe vulnerability - CVE-2022-0847)
- `hooked_syscall` (detects system call interception technique)
- `hidden_kernel_module` (detects hidden kernel modules technique)
- `hooked_proc_fops` (detects procfs file operations interception technique)
- `print_net_seq_ops` (related hooked_seq_ops event)
- `hooked_seq_ops` (detects network packets interception technique)
- `print_mem_dump` (allows memory dumping from symbols to signatures can use)

For more information and help about kernel symbols, please see [here](../advanced/ksyms.md).

## OS information

Tracee will try to probe the running OS and kernel to detect available
capabilities. For this, it needs access to some standard informative files:

- For OS information please make sure the file `/etc/os-release` is available.
- For Kernel information please make sure on of the files `/boot/config-$(uname-r)` OR `/proc/config.gz` is available.

For more information and help about OS info files, please see [here](../advanced/os-info.md).

## Process capabilities

Tracee needs non-trivial capabilities to instrument the kernel. The easiest way
is run Tracee as "privileged" or "root".  

If you want to run Tracee with "least privileges", here are the required
capabilities and justifications:

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

For more information and help about process capabilities, please see
[here](../advanced/dropping-capabilities.md).

## Processor architecture

Tracee supports x86 and arm64 processors.
