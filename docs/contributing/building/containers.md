# Creating Tracee Container Images

> These instructions are meant to describe how to build the official tracee
> containers images, instead of just downloading them from the
> [Docker Hub](https://hub.docker.com/r/aquasec/tracee).
>
> If you would like to have a local building and execution environment,
> [read this](./environment.md) instead.

## Generating Tracee Containers

Tracee containers come in **2 flavors**:

1. **tracee:latest**

    Contains an executable binary with an embedded eBPF CO-RE enabled object
    that makes it portable against multiple environments and kernel versions.

    ```text
    $ BTFHUB={0,1} make -f builder/Makefile.tracee-container build-tracee
    ```

2. **tracee:full**

    Contains tracee source tree and required toolchain in order to, during the
    startup time, compile a eBPF non CO-RE object, to your specific running
    environment, and make the executable to use on execution time.

    ```text
    $ BTFHUB={0,1} make -f builder/Makefile.tracee-container build-tracee-full
    ```

    !!! Note
        `BTFHUB=1` adds support to some [older kernels](https://github.com/aquasecurity/btfhub/blob/main/docs/supported-distros.md)
        so user doesn't need to build specific non CO-RE eBPF objects to them.

## Running Tracee Containers

Containers are supposed to be executed through docker cmdline directly, from
the official built images. Nevertheless, during the image building process, it
may be useful to execute them with correct arguments to see if they're
working.

User may execute built containers through `Makefile.tracee-container` file with
the "run" targets:

1. To run the **tracee:latest** container:

    ```text
    $ make -f builder/Makefile.tracee-container run-tracee
    ```

2. To run the **tracee:full** container:

    ```text
    $ make -f builder/Makefile.tracee-container run-tracee-full
    ```

    !!! note
        Tracee-ebpf arguments are passed through the `ARG` variable:
        ```text
        $ make -f builder/Makefile.tracee-container run-tracee ARG="--help"
        ```

## Running Tracee-eBPF Only

Generated containers allow user to run Tracee, as a complete security solution
(**tracee-ebpf** passes events to **tracee-rules** and **tracee-rules** process
events based on existing security signatures) or to run **tracee-ebpf** only,
as an introspection tool.

1. To run the `tracee:latest` container with **tracee-ebpf** only:

   ```text
   $ make -f builder/Makefile.tracee-container run-tracee-ebpf
   ```

2. To run the `tracee:full` container with **tracee-ebpf** only:

   ```text
   $ make -f builder/Makefile.tracee-container run-tracee-ebpf-full
   ```

!!! note
    Tracee-ebpf arguments are passed through the `ARG` variable:

    ```text
    $ make -f builder/Makefile.tracee-container run-tracee-ebpf ARG="--log debug"
    ```
