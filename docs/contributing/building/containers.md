# Creating Tracee Container Images

> These instructions are meant to describe how to build the official tracee
> container image, instead of just downloading it from the
> [Docker Hub](https://hub.docker.com/r/aquasec/tracee).
>
> If you would like to have a local building and execution environment,
> [read this](./environment.md) instead.

## Using Tracee Container Image from Docker Hub

Before moving on to how to build Tracee container, it is important to know the
published container images and their tag meanings. Here is the current list of
docker container images being published during a release (or a snapshot
release):

1. **SNAPSHOT (development) container images:**

     These container images are built daily and its tags always point to the
     latest daily built container images (based on the version currently being
     developed).

     - **aquasec/tracee:dev**

2. **RELEASE (official versions) container images:**

     Preferable alias for latest released image:

     - **aquasec/tracee:latest**

     And the container images for each released version of Tracee:

     - **aquasec/tracee:VERSION**

## Generating Tracee Container Images

1. **tracee:latest**

    Contains an executable binary with an embedded and CO-RE enabled eBPF object
    that makes it portable against multiple Linux and kernel versions.

    ```console
    make -f builder/Makefile.tracee-container build-tracee
    ```

    !!! Note
        `BTFHUB=1` adds support to some [older kernels](https://github.com/aquasecurity/btfhub/blob/main/docs/supported-distros.md).

        ```console
        BTFHUB=1 make -f builder/Makefile.tracee-container build-tracee
        ```

## Running Generated Tracee Container Image

Tracee container is supposed to be executed through docker cmdline directly,
from the official built images. Nevertheless, during the image building process,
it may be useful to execute the recently generated container image with correct
arguments, mostly to see if the image is working.

User may execute built containers through `Makefile.tracee-container` file with
the "run" targets:

1. To run recently generated **tracee:latest** container:

    ```console
    make -f builder/Makefile.tracee-container run-tracee
    ```

    !!! note
        Tracee arguments are passed through the `ARG` variable:
        ```console
        make -f builder/Makefile.tracee-container run-tracee ARG="--help"
        ```
