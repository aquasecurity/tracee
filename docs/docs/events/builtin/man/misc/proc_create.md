---
title: TRACEE-PROC-CREATE
section: 1
header: Tracee Event Manual
---

## NAME

**proc_create** - procfs entry creation monitoring

## DESCRIPTION

Triggered when a new entry is created in the `/proc` filesystem using the kernel's `proc_create` function. This event captures the creation of procfs entries, which are used for exposing kernel information, debugging interfaces, and system status information to user space.

Procfs entry creation is commonly used by kernel modules, drivers, and system components, but can also be used by rootkits and malware to expose hidden interfaces or maintain persistence.

## EVENT SETS

**none**

## DATA FIELDS

**name** (*string*)
: The name of the procfs entry being created

**proc_ops_addr** (*trace.Pointer*)
: The address of the proc_ops structure defining the entry's operations

## DEPENDENCIES

**Kernel Probe:**

- proc_create (required): Kernel procfs entry creation function

## USE CASES

- **Kernel module monitoring**: Track procfs entries created by legitimate kernel modules

- **Rootkit detection**: Identify unauthorized procfs entries that could indicate rootkit presence

- **System interface monitoring**: Monitor creation of system debugging and information interfaces

- **Security auditing**: Track procfs entry creation for security compliance

- **Malware analysis**: Detect malware creating procfs entries for persistence or communication

## RELATED EVENTS

- **do_init_module**: Kernel module initialization events
- **debugfs_create_file**: Debug filesystem entry creation
- **File system events**: Related filesystem and interface creation events
- **Kernel module events**: Related kernel module lifecycle monitoring
