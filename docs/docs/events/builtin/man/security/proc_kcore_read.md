---
title: TRACEE-PROC-KCORE-READ
section: 1
header: Tracee Event Manual
---

## NAME

**proc_kcore_read** - detect access to system memory through /proc/kcore

## DESCRIPTION

This event detects attempts to read the /proc/kcore file, which provides a complete image of the system's physical memory in ELF core dump format. While this file is useful for legitimate debugging purposes, it can be exploited by attackers to dump system memory, potentially exposing sensitive information like credentials, encryption keys, and process data.

Access to /proc/kcore is particularly concerning in containerized environments as it could be used for container escape attempts by providing detailed information about the host system's memory layout and contents.

## SIGNATURE METADATA

- **ID**: TRC-1021
- **Version**: 1
- **Severity**: 2
- **Category**: privilege-escalation
- **Technique**: Escape to Host
- **MITRE ID**: attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665
- **MITRE External ID**: T1611

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying security_file_open event:

**pathname** (*string*)
: Path to the file being accessed (/proc/kcore)

**flags** (*string*)
: File access flags indicating read attempt

**pid** (*int32*)
: Process ID attempting the access

**uid** (*uint32*)
: User ID performing the access

## DEPENDENCIES

- `security_file_open`: Monitor file access attempts

## USE CASES

- **Memory protection**: Prevent unauthorized memory dumps

- **Container security**: Detect potential escape attempts

- **Privilege escalation**: Identify memory inspection attempts

- **Data protection**: Prevent sensitive data exposure

## MEMORY EXPOSURE

Critical data potentially exposed:

- Encryption keys
- Authentication tokens
- Process memory
- System credentials
- Configuration data
- Runtime secrets

## ATTACK VECTORS

Common malicious uses include:

- **Memory dumping**: Extract sensitive data
- **Container escape**: Analyze host memory
- **Credential theft**: Extract authentication data
- **System analysis**: Map memory layout

## RISK ASSESSMENT

Risk factors to consider:

- **Data Exposure**: Complete memory visibility
- **Privilege Level**: Root access required
- **Attack Surface**: Host system exposure
- **Information Leak**: Sensitive data access

## LEGITIMATE USES

Valid access scenarios:

- Kernel debugging
- Memory analysis
- Crash analysis
- Performance profiling

## MITIGATION

Recommended security controls:

- Restrict /proc/kcore access
- Container isolation
- Process restrictions
- Memory protection
- Access auditing

## RELATED EVENTS

- **proc_mem_access**: Process memory access
- **proc_mem_code_injection**: Memory code injection
- **security_file_open**: File access monitoring
- **mem_prot_alert**: Memory protection alerts
