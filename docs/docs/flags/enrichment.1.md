---
title: TRACEE-ENRICHMENT
section: 1
header: Tracee Enrichment Flag Manual
date: 2025/12
...

## NAME

tracee **\-\-enrichment** - Configure enrichment for container events and other enrichment options

## SYNOPSIS

tracee **\-\-enrichment** [container|container.cgroupfs.path=*path*|container.cgroupfs.force|container.docker.socket=*socket_path*|container.containerd.socket=*socket_path*|container.crio.socket=*socket_path*|container.podman.socket=*socket_path*|resolve-fd|exec-env|exec-hash|exec-hash.mode=*mode*|user-stack-trace] [**\-\-enrichment** ...]

## DESCRIPTION

The `--enrichment` flag allows you to configure enrichment options for container events and other enrichment features.

### Flags

- **container**: Enable container enrichment with default settings. When enabled, Tracee will enrich container events with container information.

- **container.cgroupfs.path**=*path*: Enable container enrichment and configure the path to the cgroupfs where container cgroups are created. This is used as a hint for auto-detection. **Note**: Using this option automatically enables container, so you don't need to also specify `--enrichment container`.
  Example:
  ```console
  --enrichment container.cgroupfs.path=/sys/fs/cgroup
  ```

- **container.cgroupfs.force**: Force the usage of the provided mountpoint path, skipping auto-detection. **Note**: This option requires `container.cgroupfs.path` to be set. It cannot be used alone.
  Example:
  ```console
  --enrichment container.cgroupfs.path=/sys/fs/cgroup --enrichment container.cgroupfs.force
  ```

- **container.docker.socket**=*socket_path*: Enable container enrichment and configure container runtime sockets for enrichment. Configure the path to the Docker socket. **Note**: Using this option automatically enables container, so you don't need to also specify `--enrichment container`.
  Example:
  ```console
  --enrichment container.docker.socket=/var/run/docker.sock
  ```

- **container.containerd.socket**=*socket_path*: Enable container enrichment and configure container runtime sockets for enrichment. Configure the path to the Containerd socket. **Note**: Using this option automatically enables container, so you don't need to also specify `--enrichment container`.
  Example:
  ```console
  --enrichment container.containerd.socket=/var/run/containerd/containerd.sock
  ```

- **container.crio.socket**=*socket_path*: Enable container enrichment and configure container runtime sockets for enrichment. Configure the path to the CRI-O socket. **Note**: Using this option automatically enables container, so you don't need to also specify `--enrichment container`.
  Example:
  ```console
  --enrichment container.crio.socket=/var/run/crio/crio.sock
  ```

- **container.podman.socket**=*socket_path*: Enable container enrichment and configure container runtime sockets for enrichment. Configure the path to the Podman socket. **Note**: Using this option automatically enables container, so you don't need to also specify `--enrichment container`.
  Example:
  ```console
  --enrichment container.podman.socket=/var/run/podman/podman.sock
  ```

  Supported container runtimes for socket configuration:
  - CRI-O      (`crio`, `cri-o`)
  - Containerd (`containerd`)
  - Docker     (`docker`)
  - Podman     (`podman`)

- **resolve-fd**: Enable resolve-fd. When enabled, Tracee will resolve file descriptor arguments to show associated file paths instead of just the descriptor number. This enriches file descriptors with file path translation. May cause pipeline slowdowns.
  Example:
  ```console
  --enrichment resolve-fd
  ```

- **parse-arguments**: Enable parse-arguments. When enabled, Tracee will parse event arguments into human-readable strings instead of raw machine-readable values. This converts numeric flags, permissions, syscall types, and other raw values into readable format (e.g., `O_RDONLY` instead of `0`, `PROT_READ` instead of `1`). Recommended for interactive use and readability, but may add processing overhead that impacts performance on high-volume event streams.
  Example:
  ```console
  --enrichment parse-arguments
  ```

- **exec-env**: Enable exec-env. When enabled, Tracee will include execution environment variables in process execution events (particularly useful for `execve` events).
  Example:
  ```console
  --enrichment exec-env
  ```

- **exec-hash**: Enable exec-hash with default settings. When enabled, Tracee will compute hash values for executed binaries.

- **exec-hash.mode**=*mode*: Enable exec-hash and configure the mode for exec-hash. **Note**: Using this option automatically enables exec-hash, so you don't need to also specify `--enrichment exec-hash`.
  Example:
  ```console
  --enrichment exec-hash.mode=sha256
  ```

- **user-stack-trace**
  Enable user-stack-trace. Presence of the flag enables it, absence disables it.
  Example:
  ```console
  --enrichment user-stack-trace
  ```

## EXAMPLES

1. Enable container enrichment:
   ```console
   --enrichment container
   ```

2. Configure Docker socket:
   ```console
   --enrichment container.docker.socket=/var/run/docker.sock
   ```
   Note: `container.docker.socket` automatically enables container, so `--enrichment container` is not needed.

3. Set the cgroupfs path:
   ```console
   --enrichment container.cgroupfs.path=/sys/fs/cgroup
   ```
   Note: `container.cgroupfs.path` automatically enables container, so `--enrichment container` is not needed.

4. Combine multiple flags:
   ```console
   --enrichment container.docker.socket=/var/run/docker.sock --enrichment container.cgroupfs.path=/sys/fs/cgroup
   ```
   Note: Since `container.docker.socket` and `container.cgroupfs.path` automatically enable container, you don't need `--enrichment container`.

5. Enable resolve-fd, exec-env, and exec-hash:
   ```console
   --enrichment resolve-fd --enrichment exec-env --enrichment exec-hash
   ```

6. Enable exec-hash with custom mode:
   ```console
   --enrichment exec-hash.mode=sha256
   ```
   Note: `exec-hash.mode` automatically enables exec-hash, so `--enrichment exec-hash` is not needed.

Please refer to the [documentation](../install/container-engines.md) for more information on container events enrichment.

