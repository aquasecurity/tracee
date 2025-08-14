---
title: TRACEE-VFS-READ
section: 1
header: Tracee Event Manual
---

## NAME

**vfs_read** - generic filesystem file read operation

## DESCRIPTION

Triggered when a read operation from a file to a buffer is performed through the Virtual File System (VFS) layer. This event captures file read operations at the kernel VFS level, providing filesystem-agnostic monitoring of read operations.

The event hooks into the inner implementation of `read` and other buffer read syscalls after file descriptor resolution, offering detailed information about file access patterns and data consumption.

This event is useful for:

- **File access monitoring**: Track file read operations across all filesystems
- **Security analysis**: Monitor sensitive file access patterns
- **Performance analysis**: Analyze I/O patterns and performance characteristics
- **Data flow tracking**: Understand how applications consume file data

## EVENT SETS

**none**

## DATA FIELDS

**pathname** (*string*)
: The path of the file being read

**dev** (*uint32*)
: The device identifier where the file resides

**inode** (*uint64*)
: The inode number of the file on the device

**count** (*uint64*)
: The number of bytes requested to be read

**pos** (*uint64*)
: The file position offset where the read operation starts

## DEPENDENCIES

**Kernel Probes:**

- vfs_read (kprobe + kretprobe, required): VFS layer read implementation hook

## USE CASES

- **Security monitoring**: Track access to sensitive files and configuration data

- **Performance analysis**: Monitor I/O patterns and identify performance bottlenecks

- **Data leakage prevention**: Detect unusual file read patterns that might indicate data exfiltration

- **System auditing**: Monitor file access for compliance and forensic analysis

- **Application behavior analysis**: Understand how applications consume file data

## IMPLEMENTATION NOTES

- **Filesystem agnostic**: Works across all filesystem types (ext4, xfs, nfs, etc.)
- **VFS level monitoring**: Captures reads after file descriptor resolution
- **Alternative methods**: Note that files can be read through other methods like `vfs_readv`, memory mapping, and direct I/O

## LIMITATIONS

This event does not capture:
- Memory-mapped file access
- Direct I/O operations that bypass VFS
- Other read methods like `vfs_readv` (vectorized reads)

## RELATED EVENTS

- **vfs_write**: Virtual filesystem write operations
- **vfs_readv**: Vectorized read operations
- **read**: Read system call events
- **file_modification**: File modification detection events