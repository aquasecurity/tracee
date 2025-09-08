---
title: TRACEE-SWITCH-TASK-NS
section: 1
header: Tracee Event Manual
---

## NAME

**switch_task_ns** - task namespace switching monitoring

## DESCRIPTION

Triggered when a task switches between different namespaces using the kernel's `switch_task_namespaces` function. This event captures namespace transitions that occur when processes move between different namespace contexts, which is fundamental to container operations and security isolation.

Namespace switching is a core mechanism for container isolation and can also be used for privilege escalation or container escape attempts, making this event valuable for security monitoring.

## EVENT SETS

**none**

## DATA FIELDS

**pid** (*int32*)
: The process ID of the task switching namespaces

**new_mnt** (*uint32*)
: The new mount namespace identifier

**new_pid** (*uint32*)
: The new PID namespace identifier

**new_uts** (*uint32*)
: The new UTS (hostname/domain) namespace identifier

**new_ipc** (*uint32*)
: The new IPC namespace identifier

**new_net** (*uint32*)
: The new network namespace identifier

**new_cgroup** (*uint32*)
: The new cgroup namespace identifier

## DEPENDENCIES

**Kernel Probe:**

- switch_task_namespaces (required): Kernel namespace switching function

## USE CASES

- **Container security monitoring**: Track namespace transitions for security analysis

- **Container escape detection**: Identify potential container escape attempts through namespace manipulation

- **Process isolation monitoring**: Monitor namespace-based isolation effectiveness

- **Container debugging**: Debug namespace-related issues in containerized applications

- **Compliance monitoring**: Ensure namespace operations follow security policies

## RELATED EVENTS

- **init_namespaces**: Namespace initialization events
- **existing_container**: Container detection events
- **Process creation events**: Related process lifecycle monitoring
- **Security events**: Related container security monitoring
