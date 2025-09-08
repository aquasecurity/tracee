---
title: TRACEE-KERNEL-WRITE
section: 1
header: Tracee Event Manual
---

## NAME

**__kernel_write** - kernel-level write operation monitoring

## DESCRIPTION

Triggered when a write operation is performed directly by kernel code using the `__kernel_write` function. This event captures kernel-initiated write operations that bypass normal user-space write paths, providing insight into kernel-level file modifications and system operations.

These operations are typically performed by kernel subsystems, drivers, or system processes that need to write data directly to files without going through standard user-space interfaces.

## EVENT SETS

**none**

## DATA FIELDS

**pathname** (*string*)
: The path of the file being written to by kernel code

**dev** (*uint32*)
: The device identifier where the file resides

**inode** (*uint64*)
: The inode number of the file on the device

**count** (*uint64*)
: The number of bytes requested to be written

**pos** (*int64*)
: The file position offset where the write operation starts

## DEPENDENCIES

**Kernel Probe:**

- __kernel_write (kprobe + kretprobe, required): Kernel write function

## USE CASES

- **System integrity monitoring**: Track kernel-initiated file modifications

- **Security analysis**: Monitor kernel write operations for potential system compromise

- **Kernel debugging**: Analyze kernel file write patterns and behavior

- **System monitoring**: Track kernel subsystem file operations

- **Rootkit detection**: Identify unusual kernel-level file modifications

## RELATED EVENTS

- **vfs_write**: VFS layer write operations
- **vfs_writev**: Vectorized write operations
- **file_modification**: File modification detection events
- **Kernel module events**: Related kernel operation monitoring
