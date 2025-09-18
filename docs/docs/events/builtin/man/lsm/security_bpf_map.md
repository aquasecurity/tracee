---
title: TRACEE-SECURITY-BPF-MAP
section: 1
header: Tracee Event Manual
---

## NAME

**security_bpf_map** - LSM BPF map operation monitoring

## DESCRIPTION

Triggered when the Linux Security Module (LSM) framework performs security checks on BPF map operations. BPF maps are key-value stores used by BPF programs to store and share data. This event provides information about BPF map access and manipulation, including the map ID and name.

BPF maps are critical components of BPF programs and can contain sensitive data or control program behavior, making monitoring of map operations important for security and data protection.

## EVENT SETS

**lsm_hooks**

## DATA FIELDS

**map_id** (*uint32*)
: The unique identifier of the BPF map

**map_name** (*string*)
: The name of the BPF map

## DEPENDENCIES

**Kernel Probe:**

- security_bpf_map (required): LSM hook for BPF map operation security checks

## USE CASES

- **Data access monitoring**: Track access to sensitive data in BPF maps

- **BPF program analysis**: Understand data flow in BPF program ecosystems

- **Security auditing**: Monitor BPF map operations for compliance

- **Threat hunting**: Detect potential abuse of BPF maps for data exfiltration

- **Performance analysis**: Monitor BPF map usage patterns and performance

## RELATED EVENTS

- **security_bpf**: General BPF operation monitoring
- **security_bpf_prog**: BPF program monitoring events
- **bpf**: BPF system call events
- **BPF map creation events**: Related BPF map lifecycle events
