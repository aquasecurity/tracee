---
title: TRACEE-DO-INIT-MODULE
section: 1
header: Tracee Event Manual
---

## NAME

**do_init_module** - kernel module initialization monitoring

## DESCRIPTION

Triggered when a kernel module is initialized using the kernel's `do_init_module` function. This event captures kernel module loading and initialization operations, providing information about module names, versions, and source versions during the module loading process.

Kernel module loading is a privileged operation that can significantly affect system behavior and security, making monitoring of module operations important for security and system integrity.

## EVENT SETS

**none**

## DATA FIELDS

**name** (*string*)
: The name of the kernel module being initialized

**version** (*string*)
: The version of the kernel module

**src_version** (*string*)
: The source version of the kernel module

## DEPENDENCIES

**Kernel Probe:**

- do_init_module (kprobe + kretprobe, required): Kernel module initialization function

**Capabilities:**

- SYSLOG (required): Required for reading /proc/kallsyms

## USE CASES

- **Kernel security monitoring**: Track kernel module loading for security analysis

- **Rootkit detection**: Identify unauthorized kernel module loading that could indicate rootkit presence

- **System change tracking**: Monitor kernel modifications and system integrity

- **Compliance monitoring**: Ensure kernel module loading follows organizational policies

- **System debugging**: Debug kernel module loading and initialization issues

## RELATED EVENTS

- **kprobe_attach**: Kernel probe attachment often done by modules
- **proc_create**: Procfs entries often created by kernel modules
- **debugfs_create_file**: Debug filesystem entries created by modules
- **Module lifecycle events**: Related kernel module management and monitoring
