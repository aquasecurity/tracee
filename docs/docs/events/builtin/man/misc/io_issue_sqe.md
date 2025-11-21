---
title: TRACEE-IO-ISSUE-SQE
section: 1
header: Tracee Event Manual
---

## NAME

**io_issue_sqe** - io_uring submission queue entry issuance monitoring

## DESCRIPTION

Triggered when an io_uring submission queue entry (SQE) is issued for processing by the kernel. This event captures the moment when io_uring requests are dispatched for execution, providing detailed information about the operation type, target file, and execution context.

This event is crucial for understanding io_uring I/O patterns and tracking asynchronous operations as they transition from submission to execution. It captures the file being operated on, the operation type (read, write, fsync, etc.), and whether the operation is running in a dedicated kernel polling thread (SQPOLL mode) or an asynchronous worker context.

## EVENT SETS

**io_uring**

## DATA FIELDS

**path** (*string*)
: The path of the file being operated on

**device** (*uint32*)
: The device identifier where the file resides

**inode** (*uint64*)
: The inode number of the file on the device

**opcode** (*uint8*)
: The io_uring operation code (IORING_OP_READ, IORING_OP_WRITE, IORING_OP_WRITEV, etc.)

**user_data** (*uint64*)
: User-supplied data that will be echoed back in the completion event, used for tracking requests

**flags** (*uint32*)
: Request flags (e.g., REQ_F_FIXED_FILE, REQ_F_LINK, REQ_F_CLEAR_POLLIN)

**sq_thread** (*bool*)
: Whether the operation is being issued from a kernel submission queue polling thread (SQPOLL mode)

**sq_thread_id** (*uint32*)
: Thread ID of the submitting thread (useful for correlating async operations with their origin)

## DEPENDENCIES

**Kernel Probe:**

- io_uring_create (raw tracepoint, required): Required for capturing ring context
- io_issue_sqe (kprobe, required): Kernel function for issuing SQEs (kernels v5.5+)
- __io_submit_sqe (kprobe, fallback): Alternative probe for older kernels (v5.1-v5.4)

**Kernel Version Requirements:**

- Linux kernel 5.1+ for io_uring support
- io_issue_sqe function available in kernel 5.5+, fallback for 5.1-5.4

## USE CASES

- **Performance monitoring**: Track io_uring operation dispatch patterns and latency

- **Security monitoring**: Detect suspicious asynchronous I/O patterns or operations on sensitive files

- **I/O pattern analysis**: Understand application I/O behavior through io_uring

- **Debugging**: Correlate submission queue entries with their completion and file operations

- **Audit logging**: Track all asynchronous file operations for compliance

## RELATED EVENTS

- **io_uring_create**: io_uring ring creation that enables these operations
- **io_write**: Actual write operations performed via io_uring
- **vfs_write**: Traditional synchronous write operations
- **security_file_open**: File open operations that may precede io_uring operations

