---
title: TRACEE-TASK-RENAME
section: 1
header: Tracee Event Manual
---

## NAME

**task_rename** - process name change monitoring

## DESCRIPTION

Triggered when a process changes its name through the kernel's task renaming mechanism. This event captures process name changes that occur when applications modify their process titles, which can be used for legitimate purposes such as status indication or potentially for evasion techniques.

Process name changes are commonly used by daemon processes to indicate their status, but can also be used by malware to hide their identity or mimic legitimate processes.

## EVENT SETS

**proc**

## DATA FIELDS

**old_name** (*string*)
: The previous name of the process before the change

**new_name** (*string*)
: The new name assigned to the process

## DEPENDENCIES

**Kernel Tracepoint:**

- task:task_rename (required): Task renaming tracepoint

## USE CASES

- **Process identity tracking**: Monitor process name changes for identity verification

- **Security monitoring**: Detect potential process masquerading or hiding attempts

- **Process behavior analysis**: Understand process name change patterns and reasons

- **Malware detection**: Identify suspicious process renaming indicating potential threats

- **System debugging**: Debug process identity and naming issues

## RELATED EVENTS

- **execve**: Process execution events that establish initial process names
- **sched_process_fork**: Process creation events
- **Process lifecycle events**: Related process management and monitoring
- **Security process events**: Related process security monitoring
