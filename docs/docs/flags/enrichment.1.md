---
title: TRACEE-ENRICHMENT
section: 1
header: Tracee Enrichment Flag Manual
date: 2025/12
...

## NAME

tracee **\-\-enrichment** - Configure enrichment for container events and other enrichment options

## SYNOPSIS

tracee **\-\-enrichment** [container.enabled|container.cgroup.path=*path*|container.cgroup.force|container.docker.socket=*socket_path*|container.containerd.socket=*socket_path*|container.crio.socket=*socket_path*|container.podman.socket=*socket_path*|resolve-fd|exec-hash.enabled|exec-hash.mode=*mode*|user-stack-trace] [**\-\-enrichment** ...]

## DESCRIPTION

The `--enrichment` flag allows you to configure enrichment options for container events and other enrichment features.

### Flags

- **container.enabled**
  Enable container enrichment. Presence of the flag enables it, absence disables it.
  Example:
  ```console
  --enrichment container.enabled
  ```

- **container.cgroup.path**=*path*
  Configure the path to the cgroupfs where container cgroups are created. This is used as a hint for auto-detection.
  Example:
  ```console
  --enrichment container.cgroup.path=/sys/fs/cgroup
  ```

- **container.cgroup.force**
  Force cgroupfs detection. Presence of the flag enables it, absence disables it.
  Example:
  ```console
  --enrichment container.cgroup.force
  ```

- **container.docker.socket**=*socket_path*
  Configure the path to the docker socket.
  Example:
  ```console
  --enrichment container.docker.socket=/var/run/docker.sock
  ```

- **container.containerd.socket**=*socket_path*
  Configure the path to the containerd socket.
  Example:
  ```console
  --enrichment container.containerd.socket=/var/run/containerd/containerd.sock
  ```

- **container.crio.socket**=*socket_path*
  Configure the path to the crio socket.
  Example:
  ```console
  --enrichment container.crio.socket=/var/run/crio/crio.sock
  ```

- **container.podman.socket**=*socket_path*
  Configure the path to the podman socket.
  Example:
  ```console
  --enrichment container.podman.socket=/var/run/podman/podman.sock
  ```

- **resolve-fd**
  Enable resolve-fd. Presence of the flag enables it, absence disables it.
  Example:
  ```console
  --enrichment resolve-fd
  ```

- **exec-hash.enabled**
  Enable exec-hash. Presence of the flag enables it, absence disables it.
  Example:
  ```console
  --enrichment exec-hash.enabled
  ```

- **exec-hash.mode**=*mode*
  Configure the mode for exec-hash.
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
   --enrichment container.enabled
   ```

2. Configure Docker socket:
   ```console
   --enrichment container.docker.socket=/var/run/docker.sock
   ```

3. Set the cgroupfs path:
   ```console
   --enrichment container.cgroup.path=/sys/fs/cgroup
   ```

4. Combine multiple flags:
   ```console
   --enrichment container.enabled container.docker.socket=/var/run/docker.sock container.cgroup.path=/sys/fs/cgroup
   ```

5. Enable resolve-fd and exec-hash:
   ```console
   --enrichment resolve-fd exec-hash.enabled
   ```

Please refer to the [documentation](../install/container-engines.md) for more information on container events enrichment.

