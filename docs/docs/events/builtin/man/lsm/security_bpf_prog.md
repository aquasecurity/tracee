---
title: TRACEE-SECURITY-BPF-PROG
section: 1
header: Tracee Event Manual
---

## NAME

**security_bpf_prog** - security check for BPF program file descriptor generation

## DESCRIPTION

Triggered when the kernel performs a security check before generating and returning a file descriptor for a BPF program. This LSM (Linux Security Module) hook event occurs during BPF program loading or when explicitly requested by a user.

The event provides detailed information about the BPF program, including its type, name, helper functions used, and loading status. This visibility is crucial for monitoring BPF program usage and ensuring security policies are enforced.

This event is useful for:

- **BPF monitoring**: Track BPF program loading and usage
- **Security auditing**: Monitor BPF program permissions and capabilities
- **Helper function analysis**: Track which BPF helpers are being used
- **Program identification**: Monitor BPF program types and names

## EVENT SETS

**none**

## DATA FIELDS

**type** (*int32*)
: The BPF program type

**name** (*string*)
: The BPF program name (first 16 bytes only, as stored in kernel)

**helpers** (*[]uint64*)
: List of all BPF helper functions used by the program

**id** (*uint32*)
: The BPF program ID assigned by the kernel

**load** (*bool*)
: Whether this BPF program is currently being loaded

## DEPENDENCIES

**Kernel Probes:**

- security_bpf_prog (kprobe, required): LSM hook for BPF program file descriptor generation
- bpf_check (kprobe, required): Track BPF program loading status
- check_helper_call (kprobe, required): Monitor BPF helper function usage
- check_map_func_compatibility (kprobe, required): Additional BPF helper function monitoring

## USE CASES

- **Security monitoring**: Track BPF program loading and permissions

- **Helper function auditing**: Monitor which BPF helpers are being used

- **Program identification**: Track BPF program types and names

- **Load monitoring**: Detect when new BPF programs are being loaded

- **Resource tracking**: Monitor BPF program resource allocation

## BPF PROGRAM TYPES

Common BPF program types that can be monitored:

- **Socket filters**: Network packet filtering
- **Kprobes**: Kernel function tracing
- **Tracepoints**: Kernel tracepoint monitoring
- **XDP**: Network packet processing
- **Cgroup**: Control group operations

## HELPER FUNCTIONS

The event tracks BPF helper function usage:

- **Map operations**: Map access and manipulation
- **Network helpers**: Packet and socket operations
- **Tracing helpers**: Event and context information
- **Time helpers**: Timestamp and timing operations
- **Security helpers**: LSM and capability checks

## SECURITY IMPLICATIONS

Important security considerations:

- **Privilege escalation**: BPF programs can access sensitive kernel functionality
- **Resource consumption**: BPF programs can impact system performance
- **Helper restrictions**: Different program types have different helper access
- **Verification**: Programs must pass kernel verifier checks

## RELATED EVENTS

- **bpf_attach**: BPF program attachment events
- **security_bpf**: General BPF security events
- **bpf_map_create**: BPF map creation events
- **bpf_prog_load**: BPF program loading events
