---
title: TRACEE-INIT-NAMESPACES
section: 1
header: Tracee Event Manual
---

## NAME

**init_namespaces** - namespace initialization information

## DESCRIPTION

Provides information about the initial namespace configuration of the system or container environment. This event captures the namespace identifiers that represent the baseline namespace context, typically used for comparison and tracking namespace changes throughout system operation.

This event serves as a reference point for understanding namespace relationships and tracking namespace-based isolation in containerized and non-containerized environments.

## EVENT SETS

**none**

## DATA FIELDS

**cgroup** (*uint32*)
: The cgroup namespace identifier

**ipc** (*uint32*)
: The IPC namespace identifier

**mnt** (*uint32*)
: The mount namespace identifier

**net** (*uint32*)
: The network namespace identifier

**pid** (*uint32*)
: The PID namespace identifier

**pid_for_children** (*uint32*)
: The PID namespace identifier for child processes

**time** (*uint32*)
: The time namespace identifier

**time_for_children** (*uint32*)
: The time namespace identifier for child processes

**user** (*uint32*)
: The user namespace identifier

**uts** (*uint32*)
: The UTS (hostname/domain) namespace identifier

## DEPENDENCIES

**Capabilities:**

- SYS_PTRACE (required): Required capability for namespace information access

## USE CASES

- **Namespace baseline monitoring**: Establish baseline namespace configuration for tracking changes

- **Container environment analysis**: Understand initial container namespace setup

- **Security analysis**: Monitor namespace configuration for security assessment

- **System debugging**: Debug namespace-related issues by understanding initial configuration

- **Compliance monitoring**: Ensure namespace configuration meets security requirements

## RELATED EVENTS

- **switch_task_ns**: Task namespace switching events
- **existing_container**: Container detection and information events
- **Process creation events**: Related process and namespace lifecycle monitoring
- **Container lifecycle events**: Related container management events
