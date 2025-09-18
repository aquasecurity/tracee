---
title: TRACEE-SECURITY-KERNEL-READ-FILE
section: 1
header: Tracee Event Manual
---

## NAME

**security_kernel_read_file** - LSM kernel file read operation monitoring

## DESCRIPTION

Triggered when the Linux Security Module (LSM) framework performs security checks on kernel-initiated file read operations. This includes operations such as loading kernel modules, firmware, and other kernel-level file access operations that may bypass normal user-space file access controls.

This event is particularly important for security monitoring as it captures kernel-level file access that can indicate kernel module loading, firmware updates, or other system-level operations with security implications.

## EVENT SETS

**lsm_hooks**

## DATA FIELDS

**pathname** (*string*)
: The path of the file being read by the kernel

**dev** (*uint32*)
: The device number of the filesystem containing the file

**inode** (*uint64*)
: The inode number of the file

**type** (*int32*)
: The type of kernel file read operation

## DEPENDENCIES

**Kernel Probe:**

- security_kernel_read_file (required): LSM hook for kernel file read security checks

## USE CASES

- **Kernel module monitoring**: Track loading of kernel modules and drivers

- **Firmware monitoring**: Monitor firmware loading and system updates

- **Security auditing**: Detect unauthorized kernel-level file access

- **System integrity**: Monitor kernel file operations affecting system security

- **Compliance monitoring**: Ensure kernel file operations follow security policies

## RELATED EVENTS

- **security_kernel_post_read_file**: Post-read kernel file operations
- **do_init_module**: Kernel module initialization
- **Kernel module events**: Module lifecycle events
- **Firmware loading events**: Hardware initialization events
