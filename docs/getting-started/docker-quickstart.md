# Getting started with tracee with Docker 

This guide is focused on running tracee in a docker container on your local machine.

Before you proceed, make sure you follow the [prerequiresites].

[pre-requiresites]: ./installing/prerequisites.md

1. Running **tracee:{{ git.tag }}**

   ```text
   docker run \
        --name tracee --rm -it \
        --pid=host --cgroupns=host --privileged \
        -v /etc/os-release:/etc/os-release-host:ro \
        -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
        aquasec/tracee:{{ git.tag[1:] }}
   ```

2. Running **tracee:full**

   ```text
   docker run \
        --name tracee --rm -it \
        --pid=host --cgroupns=host --privileged \
        -v /etc/os-release:/etc/os-release-host:ro \
        -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
        -v /usr/src:/usr/src:ro \
        -v /lib/modules:/lib/modules:ro \
        -v /tmp/tracee:/tmp/tracee:rw \
        aquasec/tracee:full
   ```

!!! Notes

    1. The default (latest) image is **lightweight** and **portable**. It is
       supposed to support different kernel versions without having to build
       source code. If the host kernel does not support BTF then you may use
       the **full** container image. The full container will compile an eBPF
       object during startup, if you do not have one already cached in
       `/tmp/tracee`.

    2. You may need to change the volume mounts for the kernel headers based on
       your setup. See [Linux Headers](../getting-started/installing/headers.md) section for
       more info.

    3. Tracee supports enriching events with additional data from running
       containers. In order to enable this capability please look
       [here](../docs/integrating/container-engines.md).

These docker commands run Tracee with **default settings** and start
**reporting detections** to **standard output**. In order to simulate a
suspicious behavior, you can simply run:

```text
strace ls
```

in another terminal. This will trigger the **Anti-Debugging** signature, which
is loaded by default, and you will get a warning:

```
INFO: probing tracee-ebpf capabilities...
INFO: starting tracee-ebpf...
INFO: starting tracee-rules...
Loaded 14 signature(s): [TRC-1 TRC-13 TRC-2 TRC-14 TRC-3 TRC-11 TRC-9 TRC-4 TRC-5 TRC-12 TRC-8 TRC-6 TRC-10 TRC-7]
Serving metrics endpoint at :3366
Serving metrics endpoint at :4466

*** Detection ***
Time: 2022-03-25T08:04:22Z
Signature ID: TRC-2
Signature: Anti-Debugging
Data: map[]
Command: strace
Hostname: ubuntu-impish
```
