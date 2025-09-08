---
title: TRACEE-MAGIC-WRITE
section: 1
header: Tracee Event Manual
---

## NAME

**magic_write** - write operation to a file which changed the file's headers

## DESCRIPTION

Triggered when a write operation occurs at offset 0 of a file, indicating either a new file creation or modification of an existing file's headers. This event is crucial for monitoring file content changes, particularly focusing on the initial bytes that often contain file type identification and metadata.

The event provides detailed information about the written file, including its path, initial content bytes, and filesystem metadata. This information is valuable for identifying potential threats through file type analysis and content inspection.

## EVENT SETS

**none**

## DATA FIELDS

**pathname** (*string*)
: The path of the file being written

**bytes** (*[]byte*)
: The first 20 bytes of the file's content

**dev** (*uint32*)
: The device identifier where the file resides

**inode** (*uint64*)
: The inode number of the file in the filesystem

## DEPENDENCIES

**Kernel Probes:**

- vfs_write (kprobe + kretprobe, required): Catch write operations via write syscall
- vfs_writev (kprobe + kretprobe, required): Catch write operations via writev syscall
- __kernel_write (kprobe + kretprobe, required): Catch kernel-space write operations

## USE CASES

- **Malware detection**: Identify malicious file modifications or creations

- **File integrity monitoring**: Track changes to critical system files

- **Security analysis**: Monitor file content modifications for potential threats

- **Compliance monitoring**: Track file modifications for audit requirements

- **File type verification**: Ensure files maintain their expected types

## LIMITATIONS

The event has specific limitations to prevent excessive event generation:

- Does not trigger for FIFO files
- Does not trigger for files without persistent offsets
- Only captures the first 20 bytes of content
- Subject to TOCTOU (Time of Check, Time of Use) race conditions

## WRITE OPERATIONS

The event captures writes from multiple sources:

- **User-space writes**: Through write() and writev() syscalls
- **Kernel-space writes**: Through __kernel_write operations
- **Zero-offset writes**: Only triggers for writes at file offset 0

## SECURITY CONSIDERATIONS

- **TOCTOU vulnerabilities**: File content may change between detection and analysis
- **Race conditions**: Multiple writes may occur between event triggers
- **Header spoofing**: Malicious files may attempt to masquerade as other types
- **Partial writes**: Only initial bytes are captured, missing subsequent modifications

## RELATED EVENTS

- **write**: Write system call events
- **writev**: Vectored write system call events
- **vfs_write**: Virtual filesystem write events
- **vfs_writev**: Virtual filesystem vectored write events
- **security_file_open**: File open security events
