## Prerequisites

- Linux kernel version >= 4.18
- Relevant kernel headers available under conventional location (see [Linux Headers](../options/#linux-headers) section for info)
- libc, and the libraries: libelf and zlib
- clang >= 9

## Exceptions

- Tracee supports loading a pre-compiled eBPF file, in which case the kernel headers are required only for the one-time compilation, and not at runtime. See Setup Options for more info.
- When using Tracee's Docker image, all of the aforementioned requirements are built into the image. The only requirement left is the kernel headers or the pre-built eBPF. See Setup Options for more info.
