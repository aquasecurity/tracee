---
title: TRACEE-HIDDEN-KERNEL-MODULE
section: 1
header: Tracee Event Manual
---

## NAME

**hidden_kernel_module** - a hidden Linux kernel module was detected

## DESCRIPTION

Triggered when a loaded but hidden kernel module is detected on the system. This event provides a strong indication of system compromise, as hidden kernel modules are commonly used by rootkits and other malicious software to maintain persistence while avoiding detection.

The event periodically scans the system to identify kernel modules that are loaded in memory but hidden from standard module listing mechanisms.

This event is useful for:

- **Rootkit detection**: Identify hidden kernel modules used by rootkits
- **System compromise detection**: Strong indicator of system compromise
- **Security monitoring**: Continuous surveillance for stealth techniques

## EVENT SETS

**none**

## DATA FIELDS

**address** (*string*)
: The memory address of the hidden kernel module

**name** (*string*)
: The name of the hidden kernel module

**srcversion** (*string*)
: The source version string of the kernel module

## DEPENDENCIES

- `hidden_kernel_module_seeker`: Internal event that performs periodic scanning for hidden modules

## USE CASES

- **Rootkit detection**: Identify kernel-level rootkits hiding from detection

- **Security incident response**: Detect advanced persistent threats using kernel modules

- **System integrity monitoring**: Ensure no unauthorized kernel modules are hidden

- **Compliance verification**: Verify system integrity for security standards

## RELATED EVENTS

- **module_load**: Kernel module loading events
- **module_free**: Kernel module unloading events
- **symbols_loaded**: Symbol loading detection
- **ftrace_hook**: Function tracing hook detection