---
title: TRACEE-CAP-CAPABLE
section: 1
header: Tracee Event Manual
---

## NAME

**cap_capable** - capability permission check monitoring

## DESCRIPTION

Triggered when the Linux Security Module (LSM) framework checks whether a process has a specific capability. Capabilities in Linux divide the privileges traditionally associated with the superuser into distinct units that can be independently enabled or disabled.

This event provides insight into capability checks happening at the kernel level, which is essential for understanding privilege escalation attempts, security policy enforcement, and debugging permission-related issues.

## EVENT SETS

**none**

## DATA FIELDS

**cap** (*int32*)
: The capability being checked (e.g., CAP_SYS_ADMIN, CAP_NET_RAW, CAP_DAC_OVERRIDE)

## DEPENDENCIES

**Kernel Probe:**

- cap_capable (required): Kernel capability checking function

## USE CASES

- **Privilege escalation detection**: Monitor unusual capability requests

- **Security auditing**: Track capability usage across applications

- **Permission debugging**: Understand capability-related access failures

- **Compliance monitoring**: Ensure capability usage follows security policies

- **Threat hunting**: Identify suspicious capability patterns

## RELATED EVENTS

- **setuid, setgid**: User/group ID manipulation
- **execve**: Process execution with capability inheritance
- **Security syscalls**: Capability-related system calls
- **Container events**: Container capability management