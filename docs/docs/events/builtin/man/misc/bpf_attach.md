---
title: TRACEE-BPF-ATTACH
section: 1
header: Tracee Event Manual
---

## NAME

**bpf_attach** - a BPF program is attached to a probe

## DESCRIPTION

Triggered when a BPF program is attached to a kernel instrumentation point (kprobe, uprobe, tracepoint, or raw_tracepoint). This event provides information about both the BPF program and the probe it's being attached to.

This event is useful for:

- Monitoring BPF program deployment
- Security auditing of kernel instrumentation
- Understanding system behavior changes

## EVENT SETS

**none**

## DATA FIELDS

**prog_type** (*int32*)
: The type of BPF program (e.g., kprobe, tracepoint)

**prog_name** (*string*)
: Name of the BPF program (truncated to 16 characters)

**prog_id** (*uint32*)
: Unique kernel identifier for the BPF program

**prog_helpers** (*[]string*)
: List of BPF helper functions used by this program

**symbol_name** (*string*)
: Name or path of the kernel symbol being instrumented

**symbol_addr** (*uint64*)
: Memory address of the instrumentation point

**attach_type** (*int32*)
: Numeric identifier for the probe type

## DEPENDENCIES

**Kernel Probes:**

- security_file_ioctl (required)
- security_bpf_prog (required)
- security_bpf (required)
- tracepoint_probe_register_prio_may_exist (required)
- check_helper_call (optional)
- check_map_func_compatibility (optional)

## USE CASES

- **Security monitoring**: Detect unauthorized BPF program installation

- **Performance analysis**: Track when monitoring tools attach to kernel functions

- **Debugging**: Understand which BPF programs are active in the system

## RELATED EVENTS

- **security_bpf_prog**: BPF program loading and verification
- **bpf_map_create**: BPF map creation events