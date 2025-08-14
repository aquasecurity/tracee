---
title: TRACEE-SCHED-DEBUG-RECON
section: 1
header: Tracee Event Manual
---

## NAME

**sched_debug_recon** - detect reconnaissance through scheduler debug files

## DESCRIPTION

This event detects attempts to read the scheduler debug files (/proc/sched_debug and /sys/kernel/debug/sched/debug), which provide detailed information about the system's CPU scheduling and running processes. While these files are intended for debugging purposes, they can be exploited by attackers for system reconnaissance.

The information exposed through these files can help attackers understand system resource usage, process relationships, and scheduling patterns, potentially aiding in the planning of further attacks or resource exhaustion attempts.

## SIGNATURE METADATA

- **ID**: TRC-1029
- **Version**: 1
- **Severity**: 1
- **Category**: discovery
- **Technique**: Container and Resource Discovery
- **MITRE ID**: attack-pattern--0470e792-32f8-46b0-a351-652bc35e9336
- **MITRE External ID**: T1613

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying security_file_open event:

**pathname** (*string*)
: Path to the scheduler debug file being accessed

**flags** (*string*)
: File access flags indicating read attempt

**pid** (*int32*)
: Process ID attempting the access

**uid** (*uint32*)
: User ID performing the access

## DEPENDENCIES

- `security_file_open`: Monitor file access attempts

## USE CASES

- **Reconnaissance detection**: Identify system profiling

- **Resource monitoring**: Track scheduler information access

- **System integrity**: Monitor debug file access

- **Attack preparation**: Detect pre-attack reconnaissance

## EXPOSED INFORMATION

Critical data revealed:

- CPU scheduling details
- Process run queues
- Thread priorities
- CPU load balancing
- Process migration stats
- Scheduling latencies

## ATTACK VECTORS

Common malicious uses include:

- **System profiling**: Understanding resource usage
- **Process enumeration**: Mapping running processes
- **Resource analysis**: Planning resource attacks
- **Performance profiling**: Identifying bottlenecks

## RISK ASSESSMENT

Risk factors to consider:

- **Information Disclosure**: System internals exposed
- **Attack Planning**: Aids attack preparation
- **Resource Mapping**: System behavior exposed
- **Performance Analysis**: System bottlenecks revealed

## LEGITIMATE USES

Valid access scenarios:

- Performance debugging
- Scheduler tuning
- System optimization
- Resource monitoring
- Performance analysis

## MITIGATION

Recommended security controls:

- Access restrictions
- Debug file protection
- Audit logging
- Process isolation
- Resource monitoring

## RELATED EVENTS

- **proc_kcore_read**: System memory access
- **proc_mem_access**: Process memory access
- **security_file_open**: File access monitoring
- **container_create**: Container lifecycle events
