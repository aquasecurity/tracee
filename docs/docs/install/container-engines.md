# Tracee Events Container Enrichment

Tracee events provide context about where the collected events originated from, including information about the originating container if available. To gather this information, Tracee needs to communicate with the relevant container runtime.

## Configuration

Container enrichment is configured using the `--enrichment` flag. For complete details on all enrichment options, see the [enrichment flag reference](../flags/enrichment.1.md).

### Enabling Container Enrichment

To enable container enrichment with automatic runtime detection:

```console
tracee --enrichment container
```

Or in a configuration file:

```yaml
enrichment:
  container:
    enabled: true
```

### Configuring Runtime Sockets

You can explicitly configure container runtime socket paths using the enrichment flag. This is useful when sockets are in non-standard locations or when running Tracee in containerized environments.

**CLI:**

```console
# Docker
tracee --enrichment container.docker.socket=/var/run/docker.sock

# Containerd
tracee --enrichment container.containerd.socket=/var/run/containerd/containerd.sock

# CRI-O
tracee --enrichment container.crio.socket=/var/run/crio/crio.sock

# Podman
tracee --enrichment container.podman.socket=/var/run/podman/podman.sock
```

**Configuration file:**

```yaml
enrichment:
  container:
    enabled: true
    docker-socket: /var/run/docker.sock
    containerd-socket: /var/run/containerd/containerd.sock
    crio-socket: /var/run/crio/crio.sock
    podman-socket: /var/run/podman/podman.sock
```

!!! note
    Setting any container socket option automatically enables container enrichment, so you don't need to also specify `--enrichment container`.

## Automatic Runtime Detection

Tracee will automatically search for known supported runtimes by looking for their socket files in known locations when container enrichment is enabled.

You may track if Tracee was able to find the container runtime socket by running Tracee with `debug` log level. There will be a line for each known runtime engine socket and a message sharing its status.

## Running Tracee in Containers

When running Tracee in a container, the runtime sockets must be mounted to be available for Tracee.

For example, if running Tracee using Docker with Containerd as the container runtime:

```shell
docker run --name tracee -it --rm \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run/containerd:/var/run/containerd:ro \
  aquasec/tracee:latest
```

Most container runtimes have their sockets installed by default in `/var/run`, so mounting this path can also be a good option.

## Supported Container Runtimes

Tracee supports the following container runtimes and will look for their socket files in these default locations:

| Runtime    | Default Socket Path                       |
|------------|-------------------------------------------|
| Docker     | `/var/run/docker.sock`                    |
| Containerd | `/var/run/containerd/containerd.sock`     |
| CRI-O      | `/var/run/crio/crio.sock`                 |
| Podman     | `/var/run/podman/podman.sock`             |

For more details on configuring enrichment options, see the [enrichment flag reference](../flags/enrichment.1.md).
