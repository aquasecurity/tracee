---
title: TRACEE-SYSTEM-REQUEST-KEY-MODIFICATION
section: 1
header: Tracee Event Manual
---

## NAME

**system_request_key_mod** - detect modifications to System Request Key configuration

## DESCRIPTION

This event detects modifications to the System Request Key (SysRq) configuration files. The SysRq mechanism provides direct kernel access through key combinations, allowing low-level commands to be executed regardless of system state. This powerful feature can perform actions like immediate system shutdown, memory dumps, or kernel debugging.

Due to its privileged position and powerful capabilities, modifications to SysRq configuration (/proc/sys/kernel/sysrq and /proc/sysrq-trigger) could indicate attempts to manipulate system state or gather sensitive information for container escapes.

## SIGNATURE METADATA

- **ID**: TRC-1031
- **Version**: 1
- **Severity**: 3
- **Category**: privilege-escalation
- **Technique**: Escape to Host
- **MITRE ID**: attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665
- **MITRE External ID**: T1611

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying security_file_open event:

**pathname** (*string*)
: Path to the SysRq configuration being accessed

**flags** (*string*)
: File access flags indicating modification

**pid** (*int32*)
: Process ID attempting the modification

**uid** (*uint32*)
: User ID performing the modification

## DEPENDENCIES

- `security_file_open`: Monitor configuration file access

## USE CASES

- **System protection**: Prevent unauthorized SysRq access

- **Container security**: Detect potential escape attempts

- **System integrity**: Monitor critical configuration

- **Incident response**: Track system manipulation

## SYSRQ CAPABILITIES

Critical system functions:

- Emergency sync/reboot/shutdown
- Process termination
- Memory dumps
- Kernel debugging
- CPU register dumps
- Unraw keyboard mode
- OOM killer control

## ATTACK VECTORS

Common malicious uses include:

- **System disruption**: Force shutdowns/reboots
- **Information gathering**: Memory/register dumps
- **Container escape**: Host information leakage
- **Denial of service**: System resource control

## RISK ASSESSMENT

Risk factors to consider:

- **System-Wide Impact**: Affects entire system
- **Immediate Effect**: Direct kernel access
- **Recovery Prevention**: Can prevent forensics
- **Information Exposure**: System state visible

## LEGITIMATE USES

Valid modification scenarios:

- System administration
- Emergency response
- Kernel debugging
- System recovery
- Performance analysis

## MITIGATION

Recommended security controls:

- Disable SysRq in production
- Access restrictions
- Configuration monitoring
- Audit logging
- Container isolation

## RELATED EVENTS

- **proc_kcore_read**: Kernel memory access
- **security_file_open**: File access monitoring
- **proc_mem_access**: Process memory access
- **container_create**: Container lifecycle events
