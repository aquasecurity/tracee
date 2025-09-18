---
title: TRACEE-SCHED-SWITCH
section: 1
header: Tracee Event Manual
---

## NAME

**sched_switch** - CPU scheduler context switch event

## DESCRIPTION

Triggered when the CPU scheduler switches between processes or threads on a CPU core. This event provides detailed information about both the previous and next processes, including their identifiers and command names. It captures the low-level context switching that occurs in the kernel scheduler.

This event is fundamental for understanding system scheduling behavior, CPU utilization patterns, and process execution flow at the most granular level.

## EVENT SETS

**none**

## DATA FIELDS

**cpu** (*int32*)
: The CPU core number where the context switch occurred

**prev_tid** (*int32*)
: Thread ID of the process being switched out

**prev_comm** (*string*)
: Command name of the process being switched out

**next_tid** (*int32*)
: Thread ID of the process being switched in

**next_comm** (*string*)
: Command name of the process being switched in

## DEPENDENCIES

**Kernel Tracepoint:**

- sched:sched_switch (required): Scheduler tracepoint for context switch events

## USE CASES

- **Performance analysis**: Identify excessive context switching causing performance issues

- **CPU affinity monitoring**: Track process migration between CPU cores

- **Scheduler behavior analysis**: Understand scheduling decisions and patterns

- **Real-time analysis**: Monitor scheduling latency and responsiveness

- **Process activity tracking**: Detailed view of process execution on specific CPUs

## RELATED EVENTS

- **sched_process_fork**: Process creation scheduler event
- **sched_process_exit**: Process termination scheduler event
- **sched_process_exec**: Process execution scheduler event
