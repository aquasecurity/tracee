# Running Tracee with Docker

This guide will help you get started with running Tracee as a container.

## Prerequisites

- Review the [prerequisites for running Tracee](./prerequisites.md)
- If you are an Apple Mac user, please read [the Mac FAQ](../advanced/mac.md)
- Ensure that you have Docker or a compatible container runtime

## Tracee container image

 Tracee container image is available in Docker Hub as [aquasec/tracee](https://hub.docker.com/r/aquasec/tracee).

- You can use the `latest` tag or a named version version e.g `aquasec/tracee:{{ git.tag }}`.
- If you are trying the most cutting edge features, there is also a `dev` tag which is built nightly from source.
- The Tracee image is a [Multi-platform](https://docs.docker.com/build/building/multi-platform/) image that includes a x86 and arm64 flavors. You can also access the platform-specific images directly with the `aarch64` and `x86_64` tags for the latest version or `aarch64-<version>` and `x86_64-<version>` for a specific version.  
- For most first time users, just use `aquasec/tracee`!

## Running Tracee container

 Here is the docker run command, we will analyze it next:

```shell
docker run --name tracee -it --rm \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run:/var/run:ro \
  aquasec/tracee:latest
```

 1. Docker general flags:
    - `--name` - name our container so that we can interact with it easily.
    - `--rm` - remove the container one it exits, assuming this is an interactive trial of Tracee.
    - `-it` - allow the container to interact with your terminal.
 2. Since Tracee runs in a container but is instrumenting the host, it will need access to some resources from the host:
    - `--pid=host` - share the host's [process namespace]() with Tracee's container.
    - `--cgroupns-host` - share the host's [cgroup namespace]() with Tracee's container.
    - `--privileged` - run the Tracee container as root so it has all the [required capabilities](./prerequisites.md#process-capabilities).
    - `-v /etc/os-release:/etc/os-release-host:ro` - share the host's [OS information file](./prerequisites.md#os-information) with the Tracee container.
    - `-v /var/run:/var/run` - share the host's container runtime socket for [container enrichment](./container-engines.md)

 After running this command, you should start seeing a stream of events that Tracee is emitting.

 For next steps, please read about Tracee [Policies](../policies/index.md)

## Installing Tracee

 If you are looking to permanently install Tracee, you would probably do the following:

 1. Remove interactive flags `-it` and replace with daemon flag `-d`
 2. Consider how to collect events from the container.

 Or you can follow the [Kubernetes guide](./kubernetes.md) which addresses these concerns.
