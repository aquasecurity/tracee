---
title: TRACEE-DO-EXIT
section: 1
header: Tracee Event Manual
---

## NAME

**do_exit** - kernel process exit function monitoring

## DESCRIPTION

Triggered when the kernel's `do_exit` function is invoked during process termination. This function handles the core process termination logic in the Linux kernel, including resource cleanup, parent notification, and the actual termination work.

This event provides insight into the kernel's internal process cleanup mechanisms and is more low-level compared to `sched_process_exit`. It's useful for understanding kernel-level process termination behavior and debugging process exit issues.

## EVENT SETS

**proc**, **proc_life**

## DATA FIELDS

This event currently does not capture specific arguments, but provides timing and context information about when the kernel's process exit handler is invoked.

## DEPENDENCIES

**Kernel Probe:**

- do_exit (required): Kernel function for process termination

## USE CASES

- **Kernel analysis**: Monitor kernel-level process termination activity

- **Debugging**: Debug process exit issues at the kernel implementation level

- **System monitoring**: Track kernel process cleanup operations

- **Performance analysis**: Understand timing of kernel process cleanup

- **Research**: Study kernel process management behavior

## RELATED EVENTS

- **sched_process_exit**: Process termination scheduler event
- **sched_process_fork**: Process creation scheduler event
- **exit**: Exit system call event