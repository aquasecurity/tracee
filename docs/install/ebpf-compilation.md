# eBPF Compilation

Tracee is leveraging Linux's eBPF technology, which is kernel and version sensitive. Therefore, Tracee's eBPF component needs to be specifically compiled for your hosts.

The easiest way to get started is to just let Tracee build the eBPF program for you automatically when it starts, as demonstrated by the Quickstart.  
Alternatively, you can pre-compile the eBPF program, and provide it to Tracee. There are some benefits to this approach as you will not need clang and kernel headers at runtime anymore, as well as reduced risk of invoking an external program at runtime.

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
docker run ... -v /path/in/host/tracee.bpf.123.o:/path/in/container/tracee.bpf.o -e TRACEE_BPF_FILE=/path/in/container/tracee.bpf.o aquasec/tracee
```

# eBPF CO:RE Compilation

Tracee also can utilize CO:RE (Compile once, run everywhere) technology enabled by libbpf. With this enabled, you can compile the tracee bpf object file on one system, and run it on any kernel with BTF (BPF type format) enabled. To check if your kernel has BTF enabled, check for the `CONFIG_DEBUG_INFO_BTF` in your kernel config.

Compiling with CO:RE enabled is as simple as running `make CORE=y`. This will produce a bpf object file called `dist/tracee.bpf.core.{version}`. You can ship this object file with your tracee go binary and point to it by path using the `TRACEE_BPF_FILE` environment variable.