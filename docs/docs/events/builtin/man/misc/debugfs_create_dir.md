---
title: TRACEE-DEBUGFS-CREATE-DIR
section: 1
header: Tracee Event Manual
---

## NAME

**debugfs_create_dir** - debug filesystem directory creation monitoring

## DESCRIPTION

Triggered when a new directory is created in the debug filesystem (debugfs) using the kernel's `debugfs_create_dir` function. Debugfs directories are used to organize debugging interfaces and provide hierarchical structure for kernel debugging information.

Directory creation in debugfs is typically performed by kernel modules and drivers to organize their debugging interfaces, but can also be used by malicious code to establish hidden communication structures.

## EVENT SETS

**none**

## DATA FIELDS

**name** (*string*)
: The name of the debugfs directory being created

**path** (*string*)
: The full path where the debugfs directory is being created

## DEPENDENCIES

**Kernel Probe:**

- debugfs_create_dir (required): Debug filesystem directory creation function

## USE CASES

- **Kernel debugging monitoring**: Track legitimate kernel debugging directory structure creation

- **Security monitoring**: Monitor debugfs directory creation for potential security threats

- **System organization tracking**: Track debugfs structure and organization patterns

- **Malware detection**: Detect unauthorized debugfs directory creation

- **Kernel module monitoring**: Track debugfs usage by kernel modules and drivers

## RELATED EVENTS

- **debugfs_create_file**: Debug filesystem file creation
- **proc_create**: Procfs entry creation events
- **do_init_module**: Kernel module loading that may create debugfs structures
- **Kernel debugging events**: Related kernel debugging interface monitoring
