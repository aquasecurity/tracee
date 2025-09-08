---
title: TRACEE-VFS-WRITEV
section: 1
header: Tracee Event Manual
---

## NAME

**vfs_writev** - virtual filesystem vectorized write operation monitoring

## DESCRIPTION

Triggered when a vectorized write operation (writev) is performed through the Virtual File System (VFS) layer. This event captures vectorized file write operations where multiple buffers are written to a file in a single system call, providing detailed monitoring of efficient bulk write operations.

Vectorized writes allow applications to write multiple data segments efficiently, and this event provides insight into these optimized I/O patterns at the VFS level.

## EVENT SETS

**none**

## DATA FIELDS

**pathname** (*string*)
: The path of the file being written to

**dev** (*uint32*)
: The device identifier where the file resides

**inode** (*uint64*)
: The inode number of the file on the device

**vlen** (*uint64*)
: The number of vectors (buffers) in the vectorized write operation

**pos** (*int64*)
: The file position offset where the write operation starts

## DEPENDENCIES

**Kernel Probe:**

- vfs_writev (kprobe + kretprobe, required): VFS layer vectorized write function

## USE CASES

- **I/O optimization monitoring**: Track usage of vectorized write operations for performance

- **Bulk data monitoring**: Monitor applications performing large or complex write operations

- **Security analysis**: Detect potential bulk data modification or exfiltration patterns

- **Performance analysis**: Analyze vectorized I/O patterns and efficiency

- **Application profiling**: Understand how applications use vectorized I/O operations

## RELATED EVENTS

- **vfs_write**: Standard VFS write operations
- **vfs_read**: Virtual filesystem read operations
- **\_\_kernel\_write**: Kernel-level write operations
- **file_modification**: File modification detection events
