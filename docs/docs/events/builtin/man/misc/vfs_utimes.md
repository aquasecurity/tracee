---
title: TRACEE-VFS-UTIMES
section: 1
header: Tracee Event Manual
---

## NAME

**vfs_utimes** - virtual filesystem timestamp update monitoring

## DESCRIPTION

Triggered when file timestamps (access time and modification time) are updated through the Virtual File System (VFS) layer. This event captures timestamp modification operations across all filesystems, providing monitoring of when file times are explicitly changed by applications or system operations.

The event monitors both user-initiated timestamp changes and system-level timestamp updates, offering insight into file metadata modifications that could be security-relevant.

## EVENT SETS

**none**

## DATA FIELDS

**pathname** (*string*)
: The path of the file whose timestamps are being updated

**dev** (*uint32*)
: The device identifier where the file resides

**inode** (*uint64*)
: The inode number of the file on the device

**atime** (*uint64*)
: The new access time being set

**mtime** (*uint64*)
: The new modification time being set

## DEPENDENCIES

**Kernel Probe:**

- vfs_utimes (required): VFS timestamp update function (kernels >= 5.9)
- utimes_common (required): Common timestamp function (kernels < 5.9)

## USE CASES

- **Timestamp integrity monitoring**: Track file timestamp modifications for integrity verification

- **Security analysis**: Detect potential timestamp manipulation indicating file tampering

- **Compliance monitoring**: Monitor file metadata changes for regulatory compliance

- **Forensic investigation**: Track file timestamp changes for digital forensics

- **System auditing**: Monitor timestamp update patterns for system behavior analysis

## RELATED EVENTS

- **file_modification**: General file modification detection
- **vfs_write**: File write operations that may trigger timestamp updates
- **File access events**: Related file system operations
- **Security file events**: File security monitoring events
