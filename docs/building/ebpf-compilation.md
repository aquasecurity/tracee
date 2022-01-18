# eBPF Compilation

Tracee is leveraging Linux's eBPF technology, which requires kernel level integration. Tracee supports two eBPF integration modes: a portable mode which will seamlessly run everywhere on supporting environment, as demonstrated by the quickstart, or a kernel-specific mode that requires Tracee's eBPF program to be specifically compiled for your host.

The portable option, also known as CO:RE (compile once, run everywhere), requires that your operating system support BTF (BPF Type Format). Tracee will automatically run in CO:RE mode if it detects that the environment supports it. This mode requires no intervention or preparation on your side.
You can manually detect if your environments supports it by checking if the following file exists on your machine: `/sys/kernel/btf/vmlinux` or consult the following documentation: [BPF CO-RE (Compile Once – Run Everywhere)].

If you want to run Tracee on a host without BTF support you can have Tracee build the bpf object for you at runtime. This will depend on having clang and a kernel version specific kernel-header package.

Alternatively, you can pre-compile the eBPF program, and provide it to Tracee. There are some benefits to this approach as you will not need to depend on clang and kernel headers, as well as reduced risk of invoking an external program at runtime.

## Compilation Prerequisites

Portable (CO:RE) option:

- Linux kernel version >= 4.18
- libc, and the libraries: libelf, zlib
- GNU Make >= 4.3
- clang >= 12

Kernel version specific option:

- Linux kernel version >= 4.18
- Linux kernel headers available under conventional location (see [Linux Headers] section for more info)
- libc, and the libraries: libelf, zlib
- GNU Make >= 4.3
- clang >= 12

## Compiling the eBPF program

You can build the eBPF program in the following ways:

1. Clone the repo (including submodules: `git clone --branch={{ git.tag }} --recursive https://github.com/aquasecurity/tracee.git`) and `make bpf`.
2. `make bpf DOCKER=1` to build in a Docker container which includes all development tooling.

Running this will produce a file called `tracee.bpf.$kernelversion.$traceeversion.o` under the `dist` directory.

## Using compiled eBPF program

Once you have the eBPF program artifact, you can provide it to Tracee in any of the following locations:

1. Path specified in `TRACEE_BPF_FILE` environment variable
2. `/tmp/tracee`

In this case, the full Docker image can be replaced by the lighter-weight `aquasec/tracee:slim` image. This image cannot build the eBPF program on its own, and is meant to be used when you have already compiled the eBPF program beforehand.

If using Docker, the following `docker run` options demonstrate mounting a pre-compiled eBPF artifact into the container, and pointing Tracee to use it:

```bash
docker run --name tracee --rm --privileged -it \
  -v /path/in/host/tracee.bpf.123.o:/path/in/container/tracee.bpf.o \
  -e TRACEE_BPF_FILE=/path/in/container/tracee.bpf.o \
  aquasec/tracee:slim-{{ git.tag[1:] }}
```

If using Docker on a host without BTF enabled, the following `docker run` options demonstrate mounting of required kernel headers for building the bpf object at runtime:

```bash
docker run --name tracee --rm --privileged -it \
  -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  -v /tmp/tracee:/tmp/tracee \
  aquasec/tracee:{{ git.tag[1:] }}
```

[Linux Headers]: ./headers.md
[BPF CO-RE (Compile Once – Run Everywhere)]: https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere
