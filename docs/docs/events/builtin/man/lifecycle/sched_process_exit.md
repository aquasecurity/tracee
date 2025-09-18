---
title: TRACEE-SCHED-PROCESS-EXIT
section: 1
header: Tracee Event Manual
---

## NAME

**sched_process_exit** - process termination scheduler event

## DESCRIPTION

Triggered when a process terminates and exits through the kernel's scheduler tracepoint. This event provides information about the exit status and process termination details, including the exit code and whether the entire process group is terminating.

This event captures process termination at the scheduler level, providing essential information for tracking process lifecycle, monitoring process health, and understanding application termination patterns.

## EVENT SETS

**proc**, **proc_life**

## DATA FIELDS

**exit_code** (*int32*)
: The exit code of the terminating process

**signal_code** (*int32*)
: The signal code that caused process termination

**process_group_exit** (*bool*)
: Indicates whether all threads in the process group have exited

## DEPENDENCIES

**Kernel Tracepoint:**

- sched:sched_process_exit (required): Scheduler tracepoint for process exit events
- sched:sched_process_free (required): Scheduler cleanup for process exit

## USE CASES

- **Application monitoring**: Track process health and exit status

- **Security analysis**: Detect abnormal termination patterns indicating attacks

- **Process lifecycle**: Complete process tracking from creation to termination

- **Debugging**: Analyze process failures and unexpected terminations

- **Performance analysis**: Monitor process termination patterns and overhead

## RELATED EVENTS

- **sched_process_fork**: Process creation scheduler event
- **sched_process_exec**: Process execution scheduler event
- **do_exit**: Kernel process exit function
- **exit**: Exit system call event
