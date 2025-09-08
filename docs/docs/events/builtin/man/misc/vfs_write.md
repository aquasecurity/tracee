---
title: TRACEE-VFS-WRITE
section: 1
header: Tracee Event Manual
---

## NAME

**vfs_write** - virtual filesystem write operation monitoring

## DESCRIPTION

Triggered when a write operation to a file is performed through the Virtual File System (VFS) layer. This event captures file write operations at the kernel VFS level, providing filesystem-agnostic monitoring of write operations across all supported filesystems.

The event hooks into the VFS implementation after file descriptor resolution, offering detailed information about file write patterns and data modification activities.

## EVENT SETS

**none**

## DATA FIELDS

**pathname** (*string*)
: The path of the file being written to

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

- vfs_write (kprobe + kretprobe, required): VFS layer write function

## USE CASES

- **Security monitoring**: Track modifications to sensitive files and configuration data

- **Data integrity monitoring**: Detect unauthorized file modifications and changes

- **Performance analysis**: Monitor I/O patterns and identify write bottlenecks

- **Compliance auditing**: Monitor file modifications for regulatory compliance

- **Application behavior analysis**: Understand how applications modify file data

## RELATED EVENTS

- **vfs_read**: Virtual filesystem read operations
- **vfs_writev**: Vectorized write operations
- **\_\_kernel\_write**: Kernel-level write operations
- **file_modification**: File modification detection events
