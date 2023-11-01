---
title: TRACEE-CRI
section: 1
header: Tracee CRI Flag Manual
date: 2023/10
...

## NAME

tracee **\-\-cri** - Select container runtimes to connect to for container events enrichment

## SYNOPSIS

tracee **\-\-cri** <[crio|containerd|docker|podman]:socket\> [**\-\-cri** ...] ...

## DESCRIPTION

By default, if no flag is passed, Tracee will automatically detect installed runtimes by going through known runtime socket paths, looking for the following paths:

1. **Docker**:     `/var/run/docker.sock`
2. **Containerd**: `/var/run/containerd/containerd.sock`
3. **CRI-O**:      `/var/run/crio/crio.sock`
4. **Podman**:     `/var/run/podman/podman.sock`

If runtimes are specified using the **\-\-cri** flag, only the ones passed through the flags will be connected to through the provided socket file path.

Supported runtimes are:

1. **CRI-O** (crio, cri-o)
2. **Containerd** (containerd)
3. **Docker** (docker)
4. **Podman** (podman)

## EXAMPLE

- To connect to CRI-O using the socket file path `/var/run/crio/crio.sock`, use the following flag:

  ```console
  --cri crio:/var/run/crio/crio.sock
  ```

Please refer to the [documentation](../install/container-engines.md) for more information on container events enrichment.
