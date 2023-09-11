# Docker Quickstart

This section details how you can run Tracee through a container image.

## Prerequisites

!!! The container image currently does not support AArch64 architecture. Please ensure that you are on x64 system.

Additionally, please ensure that Docker or another container runtime is working on your machine. 

Note that we will provide support for multiple platforms, such as AArch64, in upcoming releases.
In the meantime, have a look at [the Kubernetes guide](./kubernetes-quickstart).
## Run the Tracee container images

All of the Tracee container images are stored in a public registry on [Docker Hub.](https://hub.docker.com/r/aquasec/tracee)

Once your system meets the requirements, you can easily start experimenting with Tracee using the Docker image as follows:

```console
docker run \
  --name tracee --rm -it \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  aquasec/tracee:latest
```

To learn how to install Tracee in a production environment, [check out the Kubernetes guide](./kubernetes-quickstart).
