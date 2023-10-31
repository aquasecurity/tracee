# Docker Quickstart

This section details how you can run Tracee through a container image.

## Prerequisites

Please ensure that Docker or another container runtime is working on your machine.

## Run the Tracee container images

All of the Tracee container images are stored in a public registry on [Docker Hub.](https://hub.docker.com/r/aquasec/tracee)
You can easily start experimenting with Tracee using the Docker image.

### On x86 architecture, please run the following command

```console
docker run \
  --name tracee --rm -it \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  aquasec/tracee:latest
```