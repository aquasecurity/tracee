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

     Daily development images built from the latest `main` branch. Tags:

     - **aquasec/tracee:dev** (multi-arch)
     - **aquasec/tracee:x86_64-dev** (amd64 only)
     - **aquasec/tracee:aarch64-dev** (arm64 only)
     - **aquasec/tracee:dev-YYYYMMDD-HHMMSSUTC** (timestamped)

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

## Development Images

For contributors who want to test the latest changes without building from source, use the daily development images from Docker Hub.

### Available Images

```bash
# Multi-architecture (recommended)
docker pull aquasec/tracee:dev

# Architecture-specific
docker pull aquasec/tracee:x86_64-dev
docker pull aquasec/tracee:aarch64-dev

# Timestamped build
docker pull aquasec/tracee:dev-20240115-050123UTC
```

### Image Details

- Build Schedule: Daily at 05:00 UTC
- Source: Latest `main` branch
- Security: Scanned for critical vulnerabilities before publishing
- Architectures: x86_64 and ARM64

### Usage Examples

```bash
# Quick test with development image
docker run --rm -it --pid=host --privileged \
  aquasec/tracee:dev --events syscalls --output format:table

# Use in development workflows
docker run --rm --pid=host --privileged \
  -v $(pwd)/policy.yaml:/policy.yaml \
  aquasec/tracee:dev --policy /policy.yaml
```

### Guidance

Use development images for testing unreleased features and validating fixes. Do not use them in production environments.

To inspect build metadata:

```bash
docker inspect aquasec/tracee:dev | jq '.[0].Config.Labels'
docker run --rm aquasec/tracee:dev --version
```

For stable release images, see the [Installation Guide](../../docs/install/index.md).
