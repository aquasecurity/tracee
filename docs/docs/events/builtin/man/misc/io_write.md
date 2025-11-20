---
title: TRACEE-IO-WRITE
section: 1
header: Tracee Event Manual
---

## NAME

**io_write** - io_uring write operation monitoring

## DESCRIPTION

Triggered when a write operation is performed through the io_uring asynchronous I/O interface. This event captures write operations submitted via io_uring, providing detailed information about the file being written, the buffer location, write size, and position within the file.

Unlike traditional synchronous writes (vfs_write), io_uring writes are performed asynchronously, often in kernel worker threads or dedicated polling threads. This event properly attributes the write to the original submitting process, even when the actual write is performed by an io_uring worker thread, making it valuable for security monitoring and performance analysis.

## EVENT SETS

**io_uring**

## DATA FIELDS

**path** (*string*)
: The path of the file being written to

**pos** (*int64*)
: The file position offset where the write operation starts

**buf** (*pointer*)
: Pointer to the user-space buffer containing data to be written

**len** (*uint32*)
: The number of bytes to be written

**worker_host_tid** (*uint32*)
: The thread ID of the original submitting thread (important for tracking async operations back to their origin)

**device** (*uint32*)
: The device identifier where the file resides

**inode** (*uint64*)
: The inode number of the file on the device

## DEPENDENCIES

**Kernel Probe:**

- io_uring_create (raw tracepoint, required): Required for capturing ring context
- io_uring_queue_async_work (raw tracepoint, required): Required for tracking async worker context
- io_write (kprobe + kretprobe, required): Kernel function for io_uring write operations (kernels v5.5+)
- __io_submit_sqe (kprobe, fallback): Alternative probe for older kernels (v5.1-v5.4)

**Kernel Version Requirements:**

- Linux kernel 5.1+ for io_uring support
- io_write function available in kernel 5.5+, fallback for 5.1-5.4

## USE CASES

- **Security monitoring**: Track file modifications performed through io_uring to detect suspicious write patterns

- **Data integrity monitoring**: Monitor writes to sensitive files or directories

- **Performance analysis**: Analyze io_uring write patterns and their efficiency

- **Application behavior analysis**: Understand how applications use io_uring for asynchronous writes

- **Compliance auditing**: Track all file modifications including those via io_uring

- **Threat detection**: Detect malicious file writes that attempt to evade traditional monitoring

## RELATED EVENTS

- **io_uring_create**: io_uring ring creation that enables these operations
- **io_issue_sqe**: Submission queue entry issuance that initiates the write
- **vfs_write**: Traditional synchronous write operations
- **file_modification**: File modification detection events
- **security_file_open**: File open operations that may precede writes

