---
title: TRACEE-VFS-READV
section: 1
header: Tracee Event Manual
---

## NAME

**vfs_readv** - track vectored reads from the virtual filesystem

## DESCRIPTION

This event captures read operations from files using the vectored I/O interface (readv). It is triggered by the VFS (Virtual File System) layer implementation of `readv`, `preadv`, and `preadv2` system calls after file descriptor resolution.

The event provides information about the file being read, including its path and location in the filesystem, as well as details about the read operation such as the number of buffers and read position.

## EVENT SETS

**none**

## DATA FIELDS

**pathname** (*string*)
: The path of the file being read

**dev** (*uint32*)
: The device ID where the file resides

**inode** (*uint64*)
: The inode number of the file on the device

**vlen** (*uint64*)
: The number of buffers in the I/O vector for this read operation

**pos** (*int64*)
: The file offset where the read operation starts

## DEPENDENCIES

- `vfs_readv`: Kernel probe on the VFS readv implementation
- `vfs_readv_ret`: Return probe for operation completion

## USE CASES

- **I/O pattern analysis**: Understand how applications use vectored I/O

- **Performance optimization**: Identify inefficient read patterns

- **Security monitoring**: Track sensitive file access

- **Debugging**: Diagnose file read issues

## IMPLEMENTATION NOTES

- Triggered by the VFS layer, independent of specific filesystems
- Captures vectored reads from `readv`, `preadv`, and `preadv2` syscalls
- Does not capture other read methods like `read`, memory mapping, etc.
- Uses both entry and return probes for complete operation tracking

## FILE ACCESS METHODS

Common file read methods in Linux:

- **read**: Single buffer read
- **readv**: Vectored I/O (this event)
- **pread/preadv**: Positioned reads
- **mmap**: Memory-mapped I/O
- **sendfile**: Direct file-to-file transfer

## RELATED EVENTS

- **vfs_read**: Single buffer read operations
- **vfs_writev**: Vectored write operations
- **readv**: System call for vectored reads
- **preadv**: Positioned vectored reads
