## Instructions on how to use **Makefile.docker** for non-CORE eBPF

Until recently, `tracee-ebpf` binary was capable of building a non CO-RE eBPF
object during whenever the running kernel did not support CO-RE. This behavior
is now changed: From now on, it is the user responsibility to have the non
CO-RE eBPF object correctly placed in "/tmp/tracee" directory. Tracee will load
it, instead of CO-RE eBPF object, as a last resource if there is no:

1. BTF file pointed by TRACEE_BTF_FILE environment variable
2. Embedded BTF available in running kernel (/sys/kernel/btf/vmlinux)
3. BTF file embedded into "tracee-ebpf" binary (from BTFhub)

User might use "make" to install the non CO-RE object:

    $ make -f Makefile.one install-bpf-nocore

And observe BPF object from /tmp/tracee being used, if needed, just like:

    $ sudo ./dist/tracee-ebpf --debug --trace 'event!=sched*'

    OSInfo: ARCH: x86_64
    OSInfo: VERSION: "20.04.3 LTS (Focal Fossa)"
    OSInfo: ID: ubuntu
    OSInfo: ID_LIKE: debian
    OSInfo: PRETTY_NAME: "Ubuntu 20.04.3 LTS"
    OSInfo: VERSION_ID: "20.04"
    OSInfo: VERSION_CODENAME: focal
    OSInfo: KERNEL_RELEASE: 5.8.0-63-generic
    BTF: bpfenv = false, btfenv = false, vmlinux = false
    BPF: no BTF file was found or provided, trying non CO-RE eBPF at
         /tmp/tracee/tracee.bpf.5_8_0-63-generic.v0_6_5-20-g3353501.o

### Using **Makefile.docker** to generate and run non CO-RE eBPF based tracee

If you're willing to generate the non CO-RE eBPF object using the
tracee-make container, you're able to by doing:

    $ make -f builder/Makefile.docker alpine-prepare # use ubuntu also
    $ make -f builder/Makefile.docker alpine-shell   # use ubuntu also

and then, inside the docker container:

    tracee@f65bab137305[/tracee]$ make -f Makefile.one clean
    tracee@f65bab137305[/tracee]$ make -f Makefile.one tracee-ebpf
    tracee@f65bab137305[/tracee]$ make -f Makefile.one install-bpf-nocore

    tracee@f65bab137305[/tracee]$ sudo ./dist/tracee-ebpf --debug --trace 'event!=sched*'

    KConfig: warning: could not check enabled kconfig features
    (could not read /boot/config-5.8.0-63-generic: ...)
    KConfig: warning: assuming kconfig values, might have unexpected behavior
    OSInfo: KERNEL_RELEASE: 5.8.0-63-generic
    OSInfo: ARCH: x86_64
    OSInfo: VERSION: "21.04 (Hirsute Hippo)"
    OSInfo: ID: ubuntu
    OSInfo: ID_LIKE: debian
    OSInfo: PRETTY_NAME: "Ubuntu 21.04"
    OSInfo: VERSION_ID: "21.04"
    OSInfo: VERSION_CODENAME: hirsute
    BTF: bpfenv = false, btfenv = false, vmlinux = false
    BPF: no BTF file was found or provided
    BPF: trying non CO-RE eBPF at /tmp/tracee/tracee.bpf.5_8_0-63-generic.v0_6_5-20-g0b921b1.o
    KConfig: warning: assuming kconfig values, might have unexpected behavior
    TIME             UID    COMM             PID     TID     RET ...


