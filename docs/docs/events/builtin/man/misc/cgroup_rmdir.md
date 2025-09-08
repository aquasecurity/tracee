---
title: TRACEE-CGROUP-RMDIR
section: 1
header: Tracee Event Manual
---

## NAME

**cgroup_rmdir** - cgroup directory removal monitoring

## DESCRIPTION

Triggered when a cgroup directory is removed through the kernel's cgroup subsystem. This event captures the cleanup and removal of control groups, typically occurring during container termination, process cleanup, or resource group deallocation.

Cgroup removal is part of the container lifecycle and resource cleanup process, providing insight into container termination and resource deallocation patterns.

## EVENT SETS

**none**

## DATA FIELDS

**cgroup_id** (*uint64*)
: The unique identifier of the cgroup being removed

**cgroup_path** (*string*)
: The filesystem path of the cgroup directory being removed

**hierarchy_id** (*uint32*)
: The cgroup hierarchy identifier

## DEPENDENCIES

**Kernel Tracepoint:**

- cgroup:cgroup_rmdir (required): Cgroup directory removal tracepoint

## USE CASES

- **Container termination monitoring**: Track container cleanup and termination processes

- **Resource cleanup monitoring**: Monitor cgroup-based resource deallocation

- **Container lifecycle tracking**: Track complete container lifecycle from creation to cleanup

- **System resource management**: Monitor system resource group cleanup patterns

- **Container debugging**: Debug container termination and cleanup issues

## RELATED EVENTS

- **cgroup_attach_task**: Cgroup task attachment events
- **switch_task_ns**: Task namespace switching events
- **existing_container**: Container detection events
- **Process termination events**: Related process lifecycle monitoring
