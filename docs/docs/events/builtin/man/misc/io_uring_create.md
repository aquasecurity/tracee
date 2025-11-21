---
title: TRACEE-IO-URING-CREATE
section: 1
header: Tracee Event Manual
---

## NAME

**io_uring_create** - io_uring ring creation monitoring

## DESCRIPTION

Triggered when a new io_uring ring is created in the Linux kernel. io_uring is a high-performance asynchronous I/O interface introduced in Linux kernel 5.1 that enables applications to submit and complete I/O operations with minimal overhead.

This event captures the creation of io_uring instances, including submission queue (SQ) and completion queue (CQ) sizes, configuration flags, and whether kernel-side polling (SQPOLL) is enabled. The event provides critical context for understanding how applications use io_uring for asynchronous operations.

## EVENT SETS

**io_uring**

## DATA FIELDS

**ctx** (*pointer*)
: Kernel pointer to the io_ring_ctx structure representing the ring context

**sq_entries** (*uint32*)
: Number of submission queue entries allocated for the ring

**cq_entries** (*uint32*)
: Number of completion queue entries allocated for the ring

**flags** (*uint32*)
: Configuration flags used when creating the io_uring instance (e.g., IORING_SETUP_SQPOLL, IORING_SETUP_IOPOLL)

**polling** (*bool*)
: Whether kernel-side polling thread (SQPOLL) is enabled for this ring

## DEPENDENCIES

**Kernel Probe:**

- io_uring_create (raw tracepoint, required): Kernel tracepoint for io_uring ring creation (kernels v5.5+)
- io_sq_offload_start + io_sq_offload_start (kprobe + kretprobe, fallback): Alternative probes for older kernels (v5.1-v5.4)

**Kernel Version Requirements:**

- Linux kernel 5.1+ for io_uring support
- Tracepoint available in kernel 5.5+, fallback probes for 5.1-5.4

## USE CASES

- **Performance monitoring**: Track io_uring usage patterns and ring configurations

- **Security monitoring**: Detect suspicious io_uring usage that may indicate exploit attempts

- **Application analysis**: Understand how applications configure io_uring for I/O operations

- **Capacity planning**: Monitor io_uring resource allocation across the system

- **Debugging**: Correlate io_uring ring creation with subsequent I/O operations

## RELATED EVENTS

- **io_issue_sqe**: io_uring submission queue entry issuance
- **io_write**: io_uring write operations
- **vfs_write**: Traditional VFS write operations for comparison

