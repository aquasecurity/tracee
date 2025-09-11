---
title: TRACEE-CGROUP-ATTACH-TASK
section: 1
header: Tracee Event Manual
---

## NAME

**cgroup_attach_task** - cgroup task attachment monitoring

## DESCRIPTION

Triggered when a task is attached to a cgroup through the kernel's cgroup subsystem. This event captures process assignments to control groups, which are fundamental to container resource management, process isolation, and system resource control.

Cgroup attachments are core to container operations and resource management, and monitoring these operations provides insight into container lifecycle and resource allocation patterns.

## EVENT SETS

**none**

## DATA FIELDS

**cgroup_path** (*string*)
: The filesystem path of the cgroup to which the task is being attached

**comm** (*string*)
: The command name of the process being attached

**pid** (*int32*)
: The process ID of the task being attached to the cgroup

## DEPENDENCIES

**Kernel Tracepoint:**

- cgroup:cgroup_attach_task (required): Cgroup task attachment tracepoint

## USE CASES

- **Container monitoring**: Track process assignments to container control groups

- **Resource management**: Monitor cgroup-based resource allocation and management

- **Container lifecycle tracking**: Track container process organization and lifecycle

- **Security monitoring**: Detect unusual cgroup assignments indicating potential security issues

- **System debugging**: Debug cgroup-related process assignment issues

## RELATED EVENTS

- **cgroup_rmdir**: Cgroup directory removal events
- **switch_task_ns**: Task namespace switching events
- **existing_container**: Container detection events
- **Process creation events**: Related process lifecycle monitoring
