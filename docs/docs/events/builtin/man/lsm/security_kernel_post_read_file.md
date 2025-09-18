---
title: TRACEE-SECURITY-KERNEL-POST-READ-FILE
section: 1
header: Tracee Event Manual
---

## NAME

**security_kernel_post_read_file** - LSM post-read kernel file operation monitoring

## DESCRIPTION

Triggered after the Linux Security Module (LSM) framework completes security checks on kernel-initiated file read operations. This event provides information about the completion of kernel file reads, including the file path, size of data read, and the type of operation.

This event complements security_kernel_read_file by providing post-operation information, allowing for complete tracking of kernel file read operations from initiation to completion with success and data size metrics.

## EVENT SETS

**lsm_hooks**

## DATA FIELDS

**pathname** (*string*)
: The path of the file that was read by the kernel

**size** (*int64*)
: The size of data read from the file

**type** (*int32*)
: The type of kernel file read operation

## DEPENDENCIES

**Kernel Probe:**

- security_kernel_post_read_file (required): LSM hook for post-read kernel file operations

## USE CASES

- **Operation validation**: Confirm successful completion of kernel file operations

- **Data volume monitoring**: Track data read during kernel module and firmware loading

- **Performance analysis**: Measure kernel file operation efficiency and timing

- **Security auditing**: Validate completion of security-critical file operations

- **Troubleshooting**: Diagnose kernel file operation failures and issues

## RELATED EVENTS

- **security_kernel_read_file**: Pre-read kernel file operations
- **do_init_module**: Kernel module initialization completion
- **Kernel module events**: Module loading lifecycle
- **Firmware events**: Hardware initialization completion
