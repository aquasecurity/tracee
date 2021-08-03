# eBPF Compilation

Tracee has two eBPF object options. A CO:RE option, and a kernel header dependent option. Both options are built automatically with tracee-ebpf.

The CO:RE (compile once, run everywhere) option can be compiled on any machine. Running with the CO:RE bpf object requires that the host kernel is compiled with `CONFIG_DEBUG_INFO_BTF` enabled. The CO:RE bpf object is embeded into the Go userspace binary. At runtime tracee-ebpf will load the CO:RE object if BTF is enabled. Otherwise it falls back to attempting to find or build a kernel header dependent object.

If you want to run Tracee on a host without BTF support you can have Tracee build one for you at runtime (it embeds the bpf source code). This will depend on having clang and a kernel version specific kernel-header package.

Alternatively, you can pre-compile the eBPF program, and provide it to Tracee. There are some benefits to this approach as you will not need to depend on clang and kernel headers, as well as reduced risk of invoking an external program at runtime.

You can build the eBPF program in the following ways:

1. Clone the repo (including submodules: `git clone --recursive https://github.com/aquasecurity/tracee.git`) and `make bpf`.
2. `make bpf DOCKER=1` to build in a Docker container which includes all development tooling.

Running this will produce a file called `tracee.bpf.$kernelversion.$traceeversion.o` under the `dist` directory.  
Once you have the eBPF program artifact, you can provide it to Tracee in any of the following locations:

1. Path specified in `TRACEE_BPF_FILE` environment variable
2. `/tmp/tracee`

In this case, the full Docker image can be replaced by the lighter-weight `aquasec/tracee:slim` image. This image cannot build the eBPF program on its own, and is meant to be used when you have already compiled the eBPF program beforehand.

If using Docker, the following `docker run` options demonstrate mounting a pre-compiled eBPF artifact into the container, and pointing Tracee to use it:

```bash
docker run ... -v /path/in/host/tracee.bpf.123.o:/path/in/container/tracee.bpf.o aquasec/tracee
```
