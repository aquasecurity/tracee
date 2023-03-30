# Creating Tracee Container Images

> These instructions are meant to describe how to build the official tracee
> containers images, instead of just downloading them from the
> [Docker Hub](https://hub.docker.com/r/aquasec/tracee).
>
> If you would like to have a local building and execution environment,
> [read this](./environment.md) instead.

## Tracee Flavors

Tracee container images come in **2 flavors**:

1. **tracee:latest** (sometimes called "slim")

    Contains an executable binary with an embedded and CO-RE enabled eBPF object
    that makes it portable against multiple Linux and kernel versions.

2. **tracee:full**

    Contains tracee source tree, and required toolchain, in order to, during the
    startup time, compile a non CO-RE eBPF object, to your specific running
    Linux kernel , and make the executable to use it on execution time.

## Using Tracee Containers from the Docker Hub

Before moving on to how to build Tracee containers, it is important to know the
published container images and their tag meanings. Here is the current list of
docker container images being published during a release:

1. **SNAPSHOT (development) container images:**

     These container images are built daily and its tags always point to the latest
     daily built container images (based on the version currently being developed).

     - **aquasec/tracee:dev** (arch: amd64, portable)
     - **aquasec/tracee:dev-full** (arch: amd64, portable & on-demand build)

     Multiple architecture tags:

     - **aquasec/tracee:x86_64-dev**  (arch: amd64, portable)
     - **aquasec/tracee:aarch64-dev** (arch: amd64, portable)

     - **aquasec/tracee:x86_64-dev-full** (arch: amd64, portable & on-demand build)
     - **aquasec/tracee:aarch64-dev-full** (arch: amd64, portable & on-demand build)

2. **RELEASE (official versions) container images:**

     Preferable aliases for latest released images (last release):

     - **aquasec/tracee:x86_64** (arch: amd64, portable)
     - **aquasec/tracee:x86_64-full** (arch: amd64, portable & on-demand build)

     From v0.13.0 and on (arm64 support):

     - **aquasec/tracee:aarch64** (arch: amd64, portable)
     - **aquasec/tracee:aarch64-full** (arch: amd64, portable & on-demand build)

     These container images exist for each released version of Tracee:

     - **aquasec/tracee:x86_64-VERSION** (arch: amd64, portable)
     - **aquasec/tracee:x86_64-VERSION-full** (arch: amd64, portable & on-demand build)

     From v0.13.0 and on (arm64 support):

     - **aquasec/tracee:aarch64-VERSION** (arch: amd64, portable)
     - **aquasec/tracee:aarch64-VERSION-full** (arch: amd64, portable & on-demand build)

## Generating Tracee Containers

1. **tracee:latest**

    ```console
    make -f builder/Makefile.tracee-container build-tracee
    ```

2. **tracee:full**

    ```console
    make -f builder/Makefile.tracee-container build-tracee-full
    ```

    !!! Note
        `BTFHUB=1` adds support to some [older kernels](https://github.com/aquasecurity/btfhub/blob/main/docs/supported-distros.md)
        so user doesn't need to build specific non CO-RE eBPF objects to them. e.g.:
        
        ```console
        BTFHUB=1 make -f builder/Makefile.tracee-container build-tracee
        ```

## Running Generated Tracee Containers

Containers are supposed to be executed through docker cmdline directly, from
the official built images. Nevertheless, during the image building process, it
may be useful to execute them with correct arguments to see if they're
working.

User may execute built containers through `Makefile.tracee-container` file with
the "run" targets:

1. To run the **tracee:latest** container:

    ```console
    make -f builder/Makefile.tracee-container run-tracee
    ```

2. To run the **tracee:full** container:

    ```console
    make -f builder/Makefile.tracee-container run-tracee-full
    ```

    !!! note
        Tracee arguments are passed through the `ARG` variable:
        ```console
        make -f builder/Makefile.tracee-container run-tracee ARG="--help"
        ```

## Running Tracee

Generated containers allow user to run Tracee, as a complete security solution
(processing events based on existing security signatures) or only as an introspection tool.

1. To run the `tracee:latest` container with only introspection:

   ```console
   make -f builder/Makefile.tracee-container run-tracee
   ```

2. To run the `tracee:full` container with only introspection:

   ```console
   make -f builder/Makefile.tracee-container run-tracee-full
   ```

!!! note
    Tracee arguments are passed through the `ARG` variable:

    ```console
    make -f builder/Makefile.tracee-container run-tracee ARG="--log debug"
    ```
