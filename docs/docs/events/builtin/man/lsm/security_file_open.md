---
title: TRACEE-SECURITY-FILE-OPEN
section: 1
header: Tracee Event Manual
---

## NAME

**security_file_open** - LSM file open operation monitoring

## DESCRIPTION

Triggered when the Linux Security Module (LSM) framework performs security checks on file open operations. This event provides detailed information about file access attempts, including the file path, access flags, and filesystem metadata, captured at the LSM level after path resolution but before the actual file operation.

This event is particularly valuable for security monitoring as it captures file access with complete context and is commonly used by security signatures to detect access to sensitive files or suspicious file operations.

## EVENT SETS

**lsm_hooks**, **fs**, **fs_file_ops**

## DATA FIELDS

**pathname** (*string*)
: The resolved path of the file being opened

**flags** (*int32*)
: The flags used for opening the file (O_RDONLY, O_WRONLY, O_RDWR, etc.)

**dev** (*uint32*)
: The device number of the filesystem containing the file

**inode** (*uint64*)
: The inode number of the file

**ctime** (*uint64*)
: The creation/change time of the file

**syscall_pathname** (*string*)
: The original pathname from the system call

## DEPENDENCIES

**Kernel Probe:**

- security_file_open (required): LSM hook for file open security checks

## USE CASES

- **Sensitive file monitoring**: Track access to critical system files (/etc/passwd, /etc/shadow)

- **Data loss prevention**: Detect potential data exfiltration through file access patterns

- **Compliance auditing**: Monitor file access for regulatory compliance

- **Threat hunting**: Identify suspicious file access patterns indicating malware

- **Application security**: Monitor application file access for security analysis

## RELATED EVENTS

- **open, openat, openat2**: File open system calls
- **security_inode_unlink**: File deletion LSM events
- **vfs_read, vfs_write**: VFS layer file operations
- **file_modification**: File modification detection events
