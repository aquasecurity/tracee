Tracee-eBPF is made of a userspace executable (`tracee-ebpf`) that drives the eBPF program, and the eBPF program itself (`tracee.bpf.$kernelversion.$traceeversion.o`). When Tracee is started, it will look for the eBPF program in specific places and if not found, it will attempt to build the eBPF program automatically before it starts (you can control this using the `--build-policy` flag).

The eBPF program is searched in the following places (in order):

1. Path specified in `TRACEE_BPF_FILE` environment variable
2. Next to the executable (same directory)
3. `/tmp/tracee`

The easiest way to get started is to just let Tracee build the eBPF program for you automatically, as demonstrated in the previous section [Quickstart with Docker](../quickstart).  
Alternatively, you can pre-compile the eBPF program, and provide it to Tracee. There are some benefits to this approach as you will not need clang and kernel headers at runtime anymore, as well as reduced risk of invoking an external program at runtime.

You can build the eBPF program in the following ways:

1. `make bpf`
2. `make bpf DOCKER=1` to build in a Docker container which includes all development tooling.
3. There is also a handy `make all` (and the `make all DOCKER=1` variant) which builds both the executable and the eBPF program.

Once you have the eBPF program artifact, you can provide it to Tracee in any of the locations mentioned above. In this case, the full Docker image can be replaced by the lighter-weight `aquasec/tracee:slim` image. This image cannot build the eBPF program on its own, and is meant to be used when you have already compiled the eBPF program beforehand.

#### Running in container

Tracee uses a filesystem directory, by default `/tmp/tracee` to capture runtime artifacts, internal components, and other miscellaneous. When running in a container, it's useful to mount this directory in, so that the artifacts are accessible after the container exits. For example, you can add this to the docker run command `-v /tmp/tracee:/tmp/tracee`.

If running in a container, regardless if it's the full or slim image, it's advisable to reuse the eBPF program across runs by mounting it from the host to the container. This way if the container builds the eBPF program it will be persisted on the host, and if the eBPF program already exists on the host, the container will automatically discover it. If you've already mounted the `/tmp/tracee` directory from the host, you're good to go, since Tracee by default will use this location for the eBPF program. You can also mount the eBPF program file individually if it's stored elsewhere (e.g in a shared volume), for example: `-v /path/to/tracee.bpf.1_2_3.4_5_6.o:/some/path/tracee.bpf.1_2_3.4_5_6.o -e TRACEE_BPF_FILE=/some/path`. 

When using the `--capture exec` option, Tracee needs access to the host PID namespace. For Docker, add `--pid=host` to the run command.

If you are building the eBPF program in a container, you'll need to make the kernel headers available in the container. The quickstart example has broader mounts that works in a variety of cases, for demonstration purposes. If you want, you can narrow those mounts down to the specific directory that contains the headers on your setup, for example: `-v /path/to/headers:/myheaders -e KERN_HEADERS=/myheaders`. As mentioned before, a better practice for production is to pre-compile the eBPF program, in which case the kernel headers are not needed at runtime.

#### Permissions

If Tracee is not actually tracing, it doesn't need privileges. For example, just building the eBPF program, or listing the available options, can be done with a regular user.  
For actually tracing, Tracee needs to run with sufficient capabilities: 
- `CAP_SYS_RESOURCE` (to manage eBPF maps limits)
- `CAP_BPF`+`CAP_TRACING` which are available on recent kernels (>=5.8), or `SYS_ADMIN` on older kernels (to load and attach the eBPF programs).

Alternatively, running as `root` or with the `--privileged` flag of Docker, is an easy way to start.

#### Linux Headers

In order to compile the eBPF program, Tracee needs some of the Linux kernel headers. Depending on your Linux distribution, there may be different ways to obtain them.  

- On Ubuntu/Debian/Arch/Manjaro install the `linux-headers` package.
- On CentOS/Fedora install the `kernel-headers` and `kernel-devel` packages.

Normally the files will be installed in `/lib/modules/${kernel_version}/build` which is where Tracee expects them. If you have the headers elsewhere, you can set the `KERN_HEADERS` environment variable with the correct location.

> Note that it's important that the kernel headers match the exact version of kernel you are running. To check the current kernel version, run the command `uname -r`. To install a specific kernel headers version append the version to the package name: `linux-headers-$(uname -r)`.

> Note that more often than not the kernel headers files contains filesystem links to other files in other directories. Therefore, when passing the kernel headers to Tracee docker container, make sure all the necessary directories are mounted. This is why the quickstart example mounts `/usr/src` in addition to `/lib/modules`.

