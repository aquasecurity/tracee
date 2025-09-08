---
title: TRACEE-FILE-MODIFICATION
section: 1
header: Tracee Event Manual
---

## NAME

**file_modification** - a file was modified by a process

## DESCRIPTION

Triggered when a file is modified by a process. This event is submitted once between the open and close of the file to reduce event volume while still providing modification detection capabilities.

The event monitors file changes by tracking file open/close operations and detecting ctime changes during the file's lifetime. It uses kernel probes to efficiently capture file modification events without overwhelming the system with excessive events for frequently modified files.

## EVENT SETS

**none**

## DATA FIELDS

**file_path** (*string*)
: The path of the file that was modified

**dev** (*uint32*)
: The device identifier that contains this file

**inode** (*uint64*)
: The inode number of the modified file

**old_ctime** (*uint64*)
: The ctime (change time) of the file before modification

**new_ctime** (*uint64*)
: The ctime (change time) of the file after modification

## DEPENDENCIES

**Kernel Probes:**

- fd_install (kprobe, required): Captures file open operations to track files for modification events
- filp_close (kprobe, required): Captures file close operations to remove files from tracking cache
- file_update_time (kprobe + kretprobe, required): Detects ctime changes during file updates
- file_modified (kprobe + kretprobe, optional): Alternative detection of file ctime changes (kernels >= 5.3)

## USE CASES

- **File integrity monitoring**: Detect unauthorized changes to critical system files

- **Security auditing**: Monitor file modifications for compliance and security

- **Malware detection**: Identify suspicious file modification patterns

- **System debugging**: Track application file modification behavior

- **Backup systems**: Trigger backup operations based on file changes

## IMPLEMENTATION NOTES

- **Event deduplication**: Only the first modification event is submitted between file open and close
- **LRU caching**: Uses LRU map to track files, which may cause occasional duplicate events when cache is full
- **Performance optimization**: Reduces event volume for frequently modified files

## LIMITATIONS

The event may occasionally be submitted more than once between file open and close due to LRU cache eviction when the cache is full, causing tracking information to be lost.

## RELATED EVENTS

- **vfs_write**: Virtual filesystem write operations
- **vfs_read**: Virtual filesystem read operations
- **security_file_open**: LSM hook for file open operations
- **do_truncate**: File truncation operations