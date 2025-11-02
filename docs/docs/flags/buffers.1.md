---
title: TRACEE-BUFFERS
section: 1
header: Tracee Buffers Flag Manual
date: 2025/12
...

## NAME

tracee **\-\-buffers** - Configure the buffers sizes for kernel and user buffers

## SYNOPSIS

tracee **\-\-buffers** [kernel.events=<size\> | kernel.artifacts=<size\> | kernel.control-plane=<size\> | pipeline=<size\>] ... [**\-\-buffers** [kernel.events=<size\> | kernel.artifacts=<size\> | kernel.control-plane=<size\> | pipeline=<size\>] ...]

## DESCRIPTION

The **\-\-buffers** flag allows you to configure the sizes of the buffers used by tracee.

Buffer sizes for perf ring buffers (kernel.events, kernel.artifacts, kernel.control-plane) are specified in pages. The pipeline buffer size is specified in event objects. The default size for perf ring buffers is 1024 pages. The default size for the pipeline buffer is 1000 event objects.

Possible buffer options:

- **kernel.events=<size\>**: Sets the size, in pages, of the internal perf ring buffer used to submit events from the kernel.

- **kernel.artifacts=<size\>**: Sets the size, in pages, of the internal perf ring buffer used to send artifacts from the kernel.

- **kernel.control-plane=<size\>**: Sets the size, in pages, of the internal perf ring buffer used to submit events from the control plane.

- **pipeline=<size\>**: Sets the size, in event objects, of each pipeline stage's output channel.

## EXAMPLES

- To set the kernel events buffer size to 2048 pages, use the following flag:

  ```console
  --buffers kernel.events=2048
  ```

- To set multiple buffer sizes at once, use multiple flags:

  ```console
  --buffers kernel.events=2048 --buffers pipeline=20000
  ```

- To set all buffer sizes in a single command, use the following flags:

  ```console
  --buffers kernel.events=2048 --buffers kernel.artifacts=1024 --buffers kernel.control-plane=512 --buffers pipeline=20000
  ```

- To only override the kernel.artifacts buffer size while keeping other buffers at their default values, use the following flag:

  ```console
  --buffers kernel.artifacts=2048
  ```
