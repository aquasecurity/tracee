---
title: TRACEE-COMMIT-CREDS
section: 1
header: Tracee Event Manual
---

## NAME

**commit_creds** - credential change operation monitoring

## DESCRIPTION

Triggered when new credentials are committed for a process using the kernel's `commit_creds` function. This event captures credential changes including user ID, group ID, and capability modifications, providing detailed information about privilege transitions and security context changes.

Credential changes are fundamental to security monitoring as they represent privilege escalation, user switching, and security context modifications that could be legitimate operations or security threats.

## EVENT SETS

**none**

## DATA FIELDS

**old_cred** (*trace.SlimCred*)
: The previous credentials before the change

**new_cred** (*trace.SlimCred*)
: The new credentials being committed

## DEPENDENCIES

**Kernel Probe:**

- commit_creds (required): Kernel credential commit function

## USE CASES

- **Privilege escalation detection**: Monitor credential changes for potential privilege escalation attempts

- **Security auditing**: Track credential modifications for compliance and security analysis

- **Authentication monitoring**: Track user identity changes and authentication events

- **Process security tracking**: Monitor security context changes for running processes

- **Threat hunting**: Identify suspicious credential manipulation patterns

## RELATED EVENTS

- **setuid, setgid**: System calls for credential changes
- **cap_capable**: Capability checking events
- **execve**: Process execution with credential inheritance
- **Security credential events**: Related credential and authentication monitoring
