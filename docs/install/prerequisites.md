# Prerequisites

A longterm supported kernel ([kernel.org](https://kernel.org)): 4.19, 5.4, 5.10, 5.15, 5.16 (stable)

> most distributions longterm supported kernels are supported as well,
> including CentOS8 4.18 kernel.

For **tracee:latest** docker image, you should have one of the two:

* A kernel that has `/sys/kernel/btf/vmlinux` file available
* A kernel supported through [BTFHUB]

> see [libbpf CO-RE documentation] for more info

For **tracee:full** docker image:

  * **Kernel Headers** package
  * **clang** 12 or 13
  * **golang** 1.17
  * **libelf** and **libelf-dev** (or elfutils-libelf and elfutils-libelf-devel)
  * **zlib1g** and **lib1g-dev** (or zlib and zlib-devel)

# Permissions

For using the eBPF Linux subsystem, Tracee needs to run with sufficient
capabilities:

* Manage eBPF maps limits (`CAP_SYS_RESOURCE`)
* Load and Attach eBPF programs:
    1. `CAP_BPF`+`CAP_PERFMON` for recent kernels (>=5.8)
    2. or `CAP_SYS_ADMIN` for older kernels
* `CAP_SYS_PTRACE` (to collect information about processes upon startup)
* `CAP_NET_ADMIN` (to use tc for packets capture)
* `CAP_SETPCAP` (if given - used to reduce bounding set capabilities)
* `CAP_SYSLOG` (to access kernel symbols through /proc/kallsyms)
* On some environments (e.g. Ubuntu) `CAP_IPC_LOCK` might be required as well.
* On cgroup v1 environments, `CAP_SYS_ADMIN` is recommended if running from a container in 
order to allow tracee to mount the cpuset cgroup controller.

> Alternatively, run as `root` or with the `--privileged` flag of Docker.

[libbpf CO-RE documentation]: https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere
[BTFHUB]: https://github.com/aquasecurity/btfhub-archive

# Corner Cases

## Drop Capabilities Error

Tracee-ebpf and tracee-rules both try to reduce capabilities upon startup.
Some environments won't allow capabilities dropping because of permission issues (for example - AWS Lambdas). It might be a result of seccomp filter for example, restricting syscalls access. 
Failure in capabilities dropping will result tracee's exit with a matching error, to guarantee that tracee isn't running with excess capabilities without the user agreement.
To allow tracee to run with high capabilities and prevent crushing, the `--allow-high-capabilities` flag can be used.
For docker users, to allow tracee-ebpf high capabilities the environment variable `ALLOW_HIGH_CAPABILITIES=1` should be used.
