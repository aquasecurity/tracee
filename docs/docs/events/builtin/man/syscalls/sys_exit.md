---
title: TRACEE-SYS-EXIT
section: 1
header: Tracee Event Manual
---

## NAME

**sys_exit** - system call exit point monitoring

## DESCRIPTION

Triggered when any system call exit occurs at the kernel level through the raw tracepoint infrastructure. This event provides comprehensive syscall monitoring by capturing every system call after it completes processing in the kernel, regardless of the specific syscall type.

Unlike specific syscall events (e.g., `open`, `execve`, `read`) that use dedicated kprobes for targeted monitoring, `sys_exit` uses raw tracepoints to capture all syscall completions generically. This makes it ideal for broad system call analysis, performance monitoring, and comprehensive auditing scenarios.

This event fires after the system call handler executes and before returning to user space, providing visibility into all system call outcomes across the entire system.

## EVENT SETS

**none**

## DATA FIELDS

**syscall** (*int32*)
: The system call number that was exited

## DEPENDENCIES

**Kernel Tracepoint:**

- raw_syscalls:sys_exit (required): Raw tracepoint for system call exit

## USE CASES

- **Security monitoring**: Track system call success and failure patterns

- **Performance analysis**: Measure system call execution time with sys_enter

- **Error analysis**: Monitor system call failures and error conditions

- **System auditing**: Complete audit trail of system call results

- **Debugging**: Trace system call completion and return values

## IMPLEMENTATION NOTES

- **High volume**: This event generates very high volumes of data since every system call triggers it
- **Raw tracepoint**: Uses kernel raw tracepoints for maximum performance
- **Post-execution**: Captures system calls after kernel processing completes

## PERFORMANCE CONSIDERATIONS

**High Overhead Scenarios:**
- Systems with intensive system call activity
- Applications making frequent system calls
- Multi-threaded applications with concurrent system calls

**Optimization Strategies:**
- Use process or container filtering when possible
- Combine with specific system call events for targeted monitoring
- Consider sampling for high-frequency environments

## TIMING ANALYSIS

When combined with **sys_enter**, enables:

**Execution Time Measurement:**
- Calculate system call duration
- Identify performance bottlenecks
- Analyze system call overhead patterns

**Flow Analysis:**
- Track complete system call lifecycle
- Correlate entry and exit events
- Monitor system call state changes

## RELATED EVENTS

- **sys_enter**: System call entry point monitoring
- **Individual syscalls**: Specific system call events (execve, open, read, write, etc.)
- **raw_syscalls**: Raw system call tracepoints
