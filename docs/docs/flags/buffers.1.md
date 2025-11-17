---
title: TRACEE-BUFFERS
section: 1
header: Tracee Buffers Flag Manual
date: 2025/11
...

## NAME

tracee **\-\-buffers** - Configure the buffers sizes for kernel and user buffers

## SYNOPSIS

tracee **\-\-buffers** [kernel-events=<size\> | kernel-blob=<size\> | control-plane-events=<size\> | pipeline=<size\>] ... [**\-\-buffers** [kernel-events=<size\> | kernel-blob=<size\> | control-plane-events=<size\> | pipeline=<size\>] ...]

## DESCRIPTION

The **\-\-buffers** flag allows you to configure the sizes of the buffers used by tracee.

Buffer sizes for perf ring buffers (kernel-events, kernel-blob, control-plane-events) are specified in pages. The pipeline buffer size is specified in event objects. The default size for perf ring buffers is 1024 pages. The default size for the pipeline buffer is 10000 event objects.

Possible buffer options:

- **kernel-events=<size\>**: Sets the size, in pages, of the internal perf ring buffer used to submit events from the kernel.

- **kernel-blob=<size\>**: Sets the size, in pages, of the internal perf ring buffer used to send blobs from the kernel.

- **control-plane-events=<size\>**: Sets the size, in pages, of the internal perf ring buffer used to submit events from the control plane.

- **pipeline=<size\>**: Sets the size, in event objects, of each pipeline stage's output channel.

## EXAMPLES

- To set the kernel events buffer size to 2048 pages, use the following flag:

  ```console
  --buffers kernel-events=2048
  ```

- To set multiple buffer sizes at once, use multiple flags:

  ```console
  --buffers kernel-events=2048 --buffers pipeline=20000
  ```

- To set all buffer sizes in a single command, use the following flags:

  ```console
  --buffers kernel-events=2048 --buffers kernel-blob=1024 --buffers control-plane-events=512 --buffers pipeline=20000
  ```

- To only override the kernel-blob buffer size while keeping other buffers at their default values, use the following flag:

  ```console
  --buffers kernel-blob=2048
  ```
