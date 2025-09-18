---
title: TRACEE-SCHED-PROCESS-FORK
section: 1
header: Tracee Event Manual
---

## NAME

**sched_process_fork** - process fork scheduler event

## DESCRIPTION

Triggered when a new process is forked from a parent process through the kernel's scheduler tracepoint. This event provides information about both the parent and child processes at the time of process creation, including process IDs, thread IDs, namespace information, and timing data.

This event captures process creation at the scheduler level, providing process hierarchy and lineage information for understanding the process tree structure and monitoring process spawning patterns.

## EVENT SETS

**none**

## DATA FIELDS

**parent_tid** (*int32*)
: Thread ID of the parent process

**parent_ns_tid** (*int32*)
: Namespace-specific thread ID of the parent process

**parent_pid** (*int32*)
: Process ID of the parent process

**parent_ns_pid** (*int32*)
: Namespace-specific process ID of the parent process

**parent_start_time** (*time.Time*)
: Start time of the parent process

**child_tid** (*int32*)
: Thread ID of the child process

**child_ns_tid** (*int32*)
: Namespace-specific thread ID of the child process

**child_pid** (*int32*)
: Process ID of the child process

**child_ns_pid** (*int32*)
: Namespace-specific process ID of the child process

**start_time** (*time.Time*)
: Start time of the child process

**parent_process_tid** (*int32*)
: Thread ID of the parent process (when process tree source is enabled)

**parent_process_ns_tid** (*int32*)
: Namespace-specific thread ID of the parent process (when process tree source is enabled)

**parent_process_pid** (*int32*)
: Process ID of the parent process (when process tree source is enabled)

## DEPENDENCIES

**Kernel Tracepoint:**

- sched:sched_process_fork (required): Scheduler tracepoint for process fork events

## USE CASES

- **Security monitoring**: Detect unusual process spawning patterns and potential threats

- **Process lineage tracking**: Build and maintain process tree relationships

- **Container analysis**: Monitor process creation within container environments

- **Performance analysis**: Track process creation overhead and patterns

- **Digital forensics**: Analyze process creation timeline and relationships

## RELATED EVENTS

- **sched_process_exit**: Process termination scheduler event
- **sched_process_exec**: Process execution scheduler event
- **fork**: Fork system call event
- **clone**: Clone system call event
