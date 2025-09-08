---
title: TRACEE-SECURITY-BPF
section: 1
header: Tracee Event Manual
---

## NAME

**security_bpf** - LSM BPF operation monitoring

## DESCRIPTION

Triggered when the Linux Security Module (LSM) framework performs security checks on BPF (Berkeley Packet Filter) operations. This event provides information about BPF-related system calls and operations, which are increasingly important for security monitoring as BPF is used for various system-level operations including networking, tracing, and security enforcement.

BPF programs can be powerful tools but also potential security risks if misused, making this event valuable for monitoring BPF usage and detecting potential abuse.

## EVENT SETS

**lsm_hooks**

## DATA FIELDS

**cmd** (*int32*)
: The BPF command being executed (BPF_PROG_LOAD, BPF_MAP_CREATE, etc.)

## DEPENDENCIES

**Kernel Probe:**

- security_bpf (required): LSM hook for BPF operation security checks

## USE CASES

- **BPF security monitoring**: Track BPF operations for security compliance

- **Privilege monitoring**: Detect unauthorized BPF usage requiring elevated privileges

- **System integrity**: Monitor BPF operations that could affect system behavior

- **Malware detection**: Identify potential BPF-based attacks or rootkits

- **Compliance auditing**: Ensure BPF usage follows organizational policies

## RELATED EVENTS

- **bpf**: BPF system call events
- **security_bpf_map**: BPF map operation monitoring
- **security_bpf_prog**: BPF program monitoring events
- **BPF program loading events**: Related BPF lifecycle events