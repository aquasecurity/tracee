# Linux Headers

!!! Note
    The **default image** is **lightweight and portable**. It is supposed to
    **support different kernel versions** without having to build source code.
    If the host kernel [does not support BTF] then you may use the full container
    image. The full container will compile an eBPF object during startup, if
    you do not have one already cached in /tmp/tracee.

[does not support BTF]: ../../contributing/building/nocore-ebpf.md#the-need-for-a-non-co-re-ebpf-object-build


When running `tracee:full` container image, in order to compile the kernel
version specific eBPF object, Tracee needs some Linux kernel headers. Depending
on your Linux distribution, there may be different ways to obtain them.  

- Ubuntu/Debian/Arch/Manjaro: install `linux-headers` package.
- CentOS/Fedora: install `kernel-headers` and `kernel-devel` packages.
- macOS: follow the [Building on OSX](../../contributing/building/macosx.md) guidelines.

Normally the files will be installed in `/lib/modules/${kernel_version}/build`
which is where Tracee expects them. If you have the headers elsewhere, you can
set the `KERN_HEADERS` environment variable with the correct location.

!!! note
    It's important that the kernel headers match the exact version of the kernel
    you are running. To check the current kernel version, run the command
    `uname -r`. To install a specific kernel headers version append the version
    to the package name: `linux-headers-$(uname -r)`.

!!! warning
    More often than not the kernel headers files contains filesystem links to
    other files in other directories. Therefore, when passing the kernel headers
    to Tracee docker container, make sure all the necessary directories are
    mounted. This is why the quickstart example mounts `/usr/src` in addition
    to `/lib/modules`.
