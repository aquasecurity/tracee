# Prerequisites

* Linux kernel version >= 4.18

One of the following:

* BTF available under `/sys/kernel/btf/vmlinux` (see [libbpf CO-RE documentation] for more info).
* Linux kernel headers available under conventional location (see [Linux Headers](./headers.md) section for more info).
  In this case system libraries libelf and zlib are required as well.
* Tracee's eBPF probe pre-compiled (see [eBPF Compilation](./ebpf-compilation.md) section for more info).

# Permissions

For using the eBPF Linux subsystem, Tracee needs to run with sufficient capabilities:

* `CAP_SYS_RESOURCE` (to manage eBPF maps limits)
* `CAP_BPF`+`CAP_PERFMON` which are available on recent kernels (>=5.8), or `CAP_SYS_ADMIN` on older kernels (to load
  and attach the eBPF programs).
* On some environments (e.g. Ubuntu) `CAP_IPC_LOCK` might be required as well.

Alternatively, run as `root` or with the `--privileged` flag of Docker.

[libbpf CO-RE documentation]: https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere