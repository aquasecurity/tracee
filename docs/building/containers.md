# Creating Tracee container images

> These instructions are meant to describe how to build the official tracee
> containers images, instead of just downloading them from the
> [Docker Hub](https://hub.docker.com/r/aquasec/tracee). If you would like to
> have a local building building and execution environment,
> [read this](./environment.md) instead.

## Generating Tracee containers

Tracee containers come in **2 flavors**:

* `tracee:latest` (CO-RE enabled embedded tracee bpf object)

  ```
  $ BTFHUB={0,1} make -f builder/Makefile.tracee-container build-tracee
  ```

* `tracee:full` (Contains tracee bpf source code and compiler tool chain) 

  ```
  $ BTFHUB={0,1} make -f builder/Makefile.tracee-container build-tracee-full
  ```

> Note: BTFHUB=1 adds support to some [older kernels](https://github.com/aquasecurity/btfhub/blob/main/docs/supported-distros.md)
> so user doesn't need to build specific non CO-RE eBPF objects to them.

## Running Tracee containers

Containers are supposed to be executed through docker cmdline directly, from the
official built images. Nevertheless, during the image building process, it may
be usefull to execute them with correct arguments to see if they're working.

User may execute built containers through `Makefile.tracee-container` file with
the "run" targets:

* To run the `tracee:latest` container:

  ```
  $ make -f builder/Makefile.tracee-container run-tracee
  ```

* To run the `tracee:full` container:

  ```
  $ make -f builder/Makefile.tracee-container run-tracee-full
  ```

> Note: tracee-ebpf arguments are passed through the ARG="" variable
>
> ```
> $ make -f builder/Makefile.tracee-container run-tracee ARG="--help"
> ```

## Running Tracee-eBPF only

Generated containers allow user to run **tracee**, as a complete security
solution (tracee-ebpf passes events to tracee-rules & tracee-rules process
events based on existing security signatures) OR to run **tracee-ebpf** only,
as an introspection tool.

* To run the `tracee:latest` container with `tracee-ebpf` only:

  ```
  $ make -f builder/Makefile.tracee-container run-tracee-ebpf
  ```

* To run the `tracee:full` container with `tracee-ebpf` only:

  ```
  $ make -f builder/Makefile.tracee-container run-tracee-ebpf-full
  ```

> Note: tracee-ebpf arguments are passed through the ARG="" variable
>
> ```
> $ make -f builder/Makefile.tracee-container run-tracee-ebpf ARG="--debug"
> ```
