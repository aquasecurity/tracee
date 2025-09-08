---
title: TRACEE-SYS-ENTER
section: 1
header: Tracee Event Manual
---

## NAME

**sys_enter** - system call entry point monitoring

## DESCRIPTION

Triggered when any system call entry occurs at the kernel level through the raw tracepoint infrastructure. This event provides comprehensive syscall monitoring by capturing every system call before it is processed by the kernel, regardless of the specific syscall type.

Unlike specific syscall events (e.g., `open`, `execve`, `read`) that use dedicated kprobes for targeted monitoring, `sys_enter` uses raw tracepoints to capture all syscalls generically. This makes it ideal for broad system call analysis and comprehensive auditing scenarios.

This event fires before the actual system call handler executes, providing early visibility into all system call requests across the entire system.

## EVENT SETS

**none**

## DATA FIELDS

**syscall** (*int32*)
: The system call number that was entered

## DEPENDENCIES

**Kernel Tracepoint:**

- raw_syscalls:sys_enter (required): Raw tracepoint for system call entry

## USE CASES

- **Security monitoring**: Detect anomalous system call patterns

- **Performance analysis**: Understand system call frequency and overhead

- **Application debugging**: Trace system call execution flow

- **System auditing**: Complete audit trail of system call activity

- **Malware detection**: Identify suspicious system call sequences

## IMPLEMENTATION NOTES

- **High volume**: This event generates very high volumes of data since every system call triggers it
- **Raw tracepoint**: Uses kernel raw tracepoints for maximum performance
- **Early interception**: Captures system calls before kernel processing

## PERFORMANCE CONSIDERATIONS

**High Overhead Scenarios:**
- Systems with intensive system call activity
- Applications making frequent system calls
- Multi-threaded applications with concurrent system calls

**Optimization Strategies:**
- Use process or container filtering when possible
- Combine with specific system call events for targeted monitoring
- Consider sampling for high-frequency environments

## RELATED EVENTS

- **sys_exit**: System call exit point monitoring
- **Individual syscalls**: Specific system call events (execve, open, read, write, etc.)
- **raw_syscalls**: Raw system call tracepoints
