---
title: TRACEE-CONTAINERS
section: 1
header: Tracee Containers Flag Manual
date: 2025/04
...

## NAME

tracee **\-\-containers** - Configure container enrichment and runtime sockets for container events enrichment

## SYNOPSIS

tracee **\-\-containers** <[enrich=<true|false>|sockets.<runtime>=<path>|cgroupfs.path=<path>|cgroupfs.force=<true|false>\>] [**\-\-containers** ...]

## DESCRIPTION

The `--containers` flag allows you to configure container enrichment and runtime sockets for container events enrichment.

### Flags

- **enrich=<true|false>**  
  Enable or disable container enrichment.  
  Example:  
  ```console
  --containers enrich=true
  ```

- **sockets.<runtime>=<path>**  
  Configure container runtime sockets for enrichment. `<runtime>` must be one of the supported runtimes:  
  - CRI-O      (`crio`, `cri-o`)  
  - Containerd (`containerd`)  
  - Docker     (`docker`)  
  - Podman     (`podman`)  

  Example:  
  ```console
  --containers sockets.docker=/var/run/docker.sock
  ```

- **cgroupfs.path=<path>**  
  Configure the path to the cgroupfs where container cgroups are created. This is used as a hint for auto-detection.  
  Example:  
  ```console
  --containers cgroupfs.path=/sys/fs/cgroup
  ```

- **cgroupfs.force=<true|false>**  
  Force the usage of the provided mountpoint path and skip auto-detection (only applies if cgroupfs.path is provided).  
  Example:  
  ```console
  --containers cgroupfs.force=true
  ```

## EXAMPLES

1. Enable container enrichment:  
   ```console
   --containers enrich=true
   ```

2. Configure Docker socket:  
   ```console
   --containers sockets.docker=/var/run/docker.sock
   ```

3. Set the cgroupfs path and force its usage:  
   ```console
   --containers cgroupfs.path=/sys/fs/cgroup cgroupfs.force=true
   ```

4. Combine multiple flags:  
   ```console
   --containers enrich=true sockets.containerd=/var/run/containerd/containerd.sock cgroupfs.path=/sys/fs/cgroup cgroupfs.force=true
   ```

Please refer to the [documentation](../install/container-engines.md) for more information on container events enrichment.
