---
title: TRACEE-DEBUGFS-CREATE-FILE
section: 1
header: Tracee Event Manual
---

## NAME

**debugfs_create_file** - debug filesystem file creation monitoring

## DESCRIPTION

Triggered when a new file is created in the debug filesystem (debugfs) using the kernel's `debugfs_create_file` function. Debugfs is a special filesystem used for kernel debugging and exposing kernel information to user space for debugging purposes.

While debugfs is primarily used for legitimate debugging, it can also be abused by rootkits and malware to expose hidden interfaces or maintain communication channels with user space.

## EVENT SETS

**none**

## DATA FIELDS

**file_name** (*string*)
: The name of the debugfs file being created

**path** (*string*)
: The full path where the debugfs file is being created

**mode** (*uint16*)
: The file mode (permissions) for the debugfs file

**proc_ops_addr** (*trace.Pointer*)
: The address of the proc_ops structure defining the file's operations

## DEPENDENCIES

**Kernel Probe:**

- debugfs_create_file (required): Debug filesystem file creation function

## USE CASES

- **Kernel debugging monitoring**: Track legitimate kernel debugging interface creation

- **Rootkit detection**: Identify unauthorized debugfs files that could indicate rootkit presence

- **Security monitoring**: Monitor debugfs file creation for potential security threats

- **System analysis**: Track debugfs usage for system debugging and analysis

- **Malware detection**: Detect malware creating debugfs entries for communication or persistence

## RELATED EVENTS

- **debugfs_create_dir**: Debug filesystem directory creation
- **proc_create**: Procfs entry creation events
- **do_init_module**: Kernel module loading that may create debugfs entries
- **Kernel debugging events**: Related kernel debugging and analysis monitoring
