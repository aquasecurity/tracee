# Tracee Events Container Enrichment

Tracee events contain context about where they originated from. This context include information about the originating container if available. To do this, Tracee needs to communicate with the relevant container runtime.  
This document shares useful information for using and troubleshooting this feature.

## Detecting container runtime

Tracee will automatically search for known supported runtimes by looking for their socket files in known locations.  
You may track if Tracee was able to find the container runtime socket by running Tracee with `debug` log level. There will be a line to each known runtime engine socket and a message sharing it's status.

When running Tracee in a container, the runtime sockets must be mounted in order to be available for Tracee.

For example, if running Tracee using Docker, and ContainerD runtime:

```console
docker run \
    --pid=host --cgroupns=host --privileged \
    -v /etc/os-release:/etc/os-release-host:ro \
    -v /var/run/containerd:/var/run/containerd \
    aquasec/tracee
```

Most container runtimes have their sockets installed by default in `/var/run`, so mounting this path can also be a good option.

## Supported Container Runtime Engines

Tracee supports the following conatiner runtimes and will look in the following paths for their socket files:

1. Docker: `/var/run/docker.sock`
2. Containerd: `/var/run/containerd/containerd.sock`
3. CRI-O: `/var/run/crio/crio.sock`
4. Podman: `/var/run/podman/podman.sock`