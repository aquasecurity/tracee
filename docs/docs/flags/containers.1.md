---
title: TRACEE-CONTAINERS
section: 1
header: Tracee Containers Flag Manual
date: 2025/04
...

## NAME

tracee **\-\-containers** - Configure container enrichment and runtime sockets for container events enrichment

## SYNOPSIS

tracee **\-\-containers** <[enrich=<true|false>|sockets.<runtime>=<path>|cgroupfs=<path>\>] [**\-\-containers** ...]

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

- **cgroupfs=<path>**  
  Configure the path to the cgroupfs where container cgroups are created.  
  Example:  
  ```console
  --containers cgroupfs=/sys/fs/cgroup
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

3. Set the cgroupfs path:  
   ```console
   --containers cgroupfs=/sys/fs/cgroup
   ```

4. Combine multiple flags:  
   ```console
   --containers enrich=true sockets.containerd=/var/run/containerd/containerd.sock cgroupfs=/sys/fs/cgroup
   ```

Please refer to the [documentation](../install/container-engines.md) for more information on container events enrichment.
