# Tracee on Apple Mac FAQ

## Does Tracee run on MacOS?

No. Tracee runs only on Linux operating system. But you can run a Linux VM on your Mac, and then run Tracee in it. Please note though, that with this setup Tracee will only have visibility to the Linux VM it is running in, and not the host Mac machine.

## Does Tracee run on Apple Silicon?

Apple Silicon (a.k.a `M#` CPUs) utilizes the ARM64 CPU architecture. Given that [Tracee is compatible with ARM64](../install/prerequisites.md#processor-architecture), it should run on Apple Silicon as well.

## Does Tracee run in a Linux container on MacOS?

Yes. It is very common to install a container engine (e.g Docker Desktop) on MacOS and still be able to run Linux containers. This works by creating a Linux virtual machine inside your MacOS and running the container engine and all your containers from inside it. Note that with this setup Tracee will only have visibility to that Linux VM which is dedicated for the container engine, and not to your Mac machine. If you wanted to run something and see how Tracee reacts to it, you can run it as another container which should be visible to Tracee.

## Linuxkit

[linuxkit](https://github.com/linuxkit/linuxkit) is a popular Linux distribution used by Docker Desktop and other solutions.  
Linux kit does not have the Kernel Symbols Table feature properly configured by default, which is a [prerequisite](../install/prerequisites.md#kernel-symbols) for running Tracee.  
It is technically possible to enable kernel symbols in linuxkit but an easier solution would be to  disable [those Tracee events that depend on kernel symbols](../install/prerequisites.md#kernel-symbols).
