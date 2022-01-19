# Creating Tracee container images

> These instructions are meant to describe how to build the official tracee
> containers images, instead of just downloading them from the
> [Docker Hub](https://hub.docker.com/r/aquasec/tracee). If you would like to
> have a local building building and execution environment,
> [read this](./environment.md) instead.

## Generating Tracee containers

Tracee containers come in **3 flavors**:

* `tracee`: default [CO-RE eBPF](https://nakryiko.com/posts/bpf-portability-and-co-re/) tracee (portable).

  ```
  $ make -f builder/Makefile.tracee-container build-alpine-tracee-core
  ```

* `tracee-btfhub`: CO-RE eBPF tracee with [older kernels support](https://github.com/aquasecurity/btfhub/blob/main/docs/supported-distros.md).

  ```
  $ make -f builder/Makefile.tracee-container build-alpine-tracee-core-btfhub
  ```

* `tracee-nocore`: non CO-RE eBPF binary (eBPF code is compiled before the run).

  ```
  $ make -f builder/Makefile.tracee-container build-alpine-tracee-nocore
  ```

At the end you will end up with 3 docker images built. Example:

```
$ docker image ls
REPOSITORY           TAG       IMAGE ID       CREATED        SIZE
tracee-btfhub        latest    1612003190b7   11 hours ago   73.6MB
tracee-nocore        latest    cc8eba17fd76   11 hours ago   1.19GB
tracee               latest    11dd16c3bda3   11 hours ago   72.1MB
```

Then, you may chose to run the container images through the cmdline, or to use
the same Makefile.tracee-container file with targets that will run it for you.

## Executing Tracee containers

You may chose to generate container images locally or not. You're able to run
the containers images, with correct/needed docker arguments, through the
Makefile.tracee-container file.

* To run the `tracee` container:

  ```
  $ make -f builder/Makefile.tracee-container run-alpine-tracee-core
  ```

* To run the `tracee-btfhub` container:

  ```
  $ make -f builder/Makefile.tracee-container run-alpine-tracee-core-btfhub
  ```

* To run the `tracee-nocore` container:

  ```
  $ make -f builder/Makefile.tracee-container run-alpine-tracee-nocore
  ```

> You may provide arguments to tracee through the `ARG` variable to the Makefile:
>
> ```
> $ make -f builder/Makefile.tracee-container run-alpine-tracee-core ARG="--debug"
> ```

## Executing `tracee-ebpf` only

Generated tracee containers allow you to run **tracee**, as a complete solution
(tracee-ebpf passes events to tracee-rules and tracee-rules process events
based on existing signatures) OR to run **tracee-ebpf** only, as an
introspection tool.

* To run the `tracee` container with `tracee-ebpf` only:

  ```
  $ make -f builder/Makefile.tracee-container run-alpine-tracee-ebpf-core
  ```

* To run the `tracee-btfhub` container with `tracee-ebpf` only:

  ```
  $ make -f builder/Makefile.tracee-container run-alpine-tracee-ebpf-core-btfhub
  ```

* To run the `tracee-nocore` container with `tracee-ebpf` only:

  ```
  $ make -f builder/Makefile.tracee-container run-alpine-tracee-ebpf-nocore
  ```

> You may provide arguments to tracee-ebpf through the `ARG` variable to the
> Makefile:
>
> ```
> $ make -f builder/Makefile.tracee-container run-alpine-tracee-ebpf-core ARG="--debug"
> ```
