---
title: TRACEE-SET-FS-PWD
section: 1
header: Tracee Event Manual
---

## NAME

**set_fs_pwd** - track changes to the current working directory

## DESCRIPTION

This event captures changes to the current working directory (typically through `chdir` and `fchdir` syscalls). It provides both the user-supplied path and the fully resolved filesystem path, helping track directory traversal and potential path manipulation attempts.

This event is useful for:

- **Process monitoring**: Track directory changes of processes
- **Security auditing**: Monitor for suspicious directory access
- **Debugging**: Troubleshoot path-related issues
- **Compliance**: Track file system access patterns

## EVENT SETS

**none**

## DATA FIELDS

**unresolved_path** (*string*)
: The unresolved, user-supplied path for the directory change. This may contain relative paths, symlinks, or ".." components. Only available for changes using the `chdir` syscall.

**resolved_path** (*string*)
: The fully resolved filesystem path after all symlinks and relative components are resolved.

## DEPENDENCIES

- `set_fs_pwd`: Kernel probe to catch changes to the current working directory

## USE CASES

- **Directory traversal detection**: Monitor for suspicious path traversal patterns

- **Access auditing**: Track which directories processes are accessing

- **Symlink resolution**: Understand the relationship between user-provided and resolved paths

- **Process behavior analysis**: Map process directory access patterns

## IMPLEMENTATION NOTES

The event uses a kprobe on the kernel's `set_fs_pwd` function to capture directory changes. This provides visibility into:

- Direct directory changes via `chdir`
- File descriptor-based changes via `fchdir`
- Relative vs absolute path resolution
- Symlink traversal

## SECURITY IMPLICATIONS

Directory changes can indicate:

- Privilege escalation attempts through path traversal
- Data exfiltration via sensitive directory access
- Malware persistence through specific directory targeting
- Evasion techniques using path manipulation

## RELATED EVENTS

- **chdir**: System call for changing directories
- **fchdir**: File descriptor-based directory change
- **file_modification**: File operations in changed directories
- **security_path_notify**: Path-based security events
