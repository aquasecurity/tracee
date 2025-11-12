---
title: TRACEE-ENRICH
section: 1
header: Tracee Enrich Flag Manual
date: 2025/04
...

## NAME

tracee **\-\-enrich** - Configure enrichment for container events and other enrichment options

## SYNOPSIS

tracee **\-\-enrich** [container.enabled=*true|false*|container.cgroup.path=*path*|container.docker.socket=*socket_path*|container.containerd.socket=*socket_path*|container.crio.socket=*socket_path*|container.podman.socket=*socket_path*|resolve-fd=*true|false*|exec-hash.enabled=*true|false*|exec-hash.mode=*mode*|user-stack-trace=*true|false*] [**\-\-enrich** ...]

## DESCRIPTION

The `--enrich` flag allows you to configure enrichment options for container events and other enrichment features.

### Flags

- **container.enabled**=*true|false*
  Enable or disable container enrichment.
  Example:
  ```console
  --enrich container.enabled=true
  ```

- **container.cgroup.path**=*path*
  Configure the path to the cgroupfs where container cgroups are created. This is used as a hint for auto-detection.
  Example:
  ```console
  --enrich container.cgroup.path=/sys/fs/cgroup
  ```

- **container.docker.socket**=*socket_path*
  Configure the path to the docker socket.
  Example:
  ```console
  --enrich container.docker.socket=/var/run/docker.sock
  ```

- **container.containerd.socket**=*socket_path*
  Configure the path to the containerd socket.
  Example:
  ```console
  --enrich container.containerd.socket=/var/run/containerd/containerd.sock
  ```

- **container.crio.socket**=*socket_path*
  Configure the path to the crio socket.
  Example:
  ```console
  --enrich container.crio.socket=/var/run/crio/crio.sock
  ```

- **container.podman.socket**=*socket_path*
  Configure the path to the podman socket.
  Example:
  ```console
  --enrich container.podman.socket=/var/run/podman/podman.sock
  ```

- **resolve-fd**=*true|false*
  Enable or disable resolve-fd.
  Example:
  ```console
  --enrich resolve-fd=true
  ```

- **exec-hash.enabled**=*true|false*
  Enable or disable exec-hash.
  Example:
  ```console
  --enrich exec-hash.enabled=true
  ```

- **exec-hash.mode**=*mode*
  Configure the mode for exec-hash.
  Example:
  ```console
  --enrich exec-hash.mode=sha256
  ```

- **user-stack-trace**=*true|false*
  Enable or disable user-stack-trace.
  Example:
  ```console
  --enrich user-stack-trace=true
  ```

## EXAMPLES

1. Enable container enrichment:
   ```console
   --enrich container.enabled=true
   ```

2. Configure Docker socket:
   ```console
   --enrich container.docker.socket=/var/run/docker.sock
   ```

3. Set the cgroupfs path:
   ```console
   --enrich container.cgroup.path=/sys/fs/cgroup
   ```

4. Combine multiple flags:
   ```console
   --enrich container.enabled=true container.docker.socket=/var/run/docker.sock container.cgroup.path=/sys/fs/cgroup
   ```

5. Enable resolve-fd and exec-hash:
   ```console
   --enrich resolve-fd=true exec-hash.enabled=true
   ```

Please refer to the [documentation](../install/container-engines.md) for more information on container events enrichment.

