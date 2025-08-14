---
title: TRACEE-PROC-MEM-ACCESS
section: 1
header: Tracee Event Manual
---

## NAME

**proc_mem_access** - detect process memory access through /proc filesystem

## DESCRIPTION

This event detects attempts to access process memory through the /proc filesystem. In Linux, each process has a mem file in its /proc/[pid] directory that provides direct access to the process's memory space. While this interface is valuable for debugging, it can be exploited to read sensitive information like credentials, secrets, and runtime data from processes.

The event monitors access attempts to these memory files, helping detect potential credential theft, memory dumping, or other malicious attempts to extract sensitive information from running processes.

## SIGNATURE METADATA

- **ID**: TRC-1023
- **Version**: 1
- **Severity**: 3
- **Category**: credential-access
- **Technique**: Proc Filesystem
- **MITRE ID**: attack-pattern--3120b9fa-23b8-4500-ae73-09494f607b7d
- **MITRE External ID**: T1003.007

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying security_file_open event:

**pathname** (*string*)
: Path to the process memory file being accessed

**flags** (*string*)
: File access flags indicating the type of access

**pid** (*int32*)
: Process ID attempting the access

**target_pid** (*int32*)
: Process ID whose memory is being accessed

## DEPENDENCIES

- `security_file_open`: Monitor file access attempts

## USE CASES

- **Credential protection**: Prevent memory-based credential theft

- **Process integrity**: Monitor unauthorized memory access

- **Secret protection**: Protect runtime secrets

- **Attack detection**: Identify memory inspection attempts

## PROCESS MEMORY

Sensitive data in process memory:

- Authentication tokens
- Encryption keys
- Session data
- Configuration secrets
- Runtime credentials
- User input data

## ATTACK VECTORS

Common malicious uses include:

- **Credential theft**: Extract authentication data
- **Secret extraction**: Access runtime secrets
- **Memory dumping**: Capture process state
- **Data exfiltration**: Access sensitive information

## RISK ASSESSMENT

Risk factors to consider:

- **Data Exposure**: Direct memory access
- **Privilege Level**: Root access required
- **Process Impact**: Target process affected
- **Information Leak**: Sensitive data access

## LEGITIMATE USES

Valid memory access scenarios:

- Process debugging
- Memory analysis
- Crash investigation
- Performance profiling

## MITIGATION

Recommended security controls:

- Process isolation
- Memory protection
- Access restrictions
- Audit logging
- Privilege control

## RELATED EVENTS

- **proc_kcore_read**: System memory access
- **proc_mem_code_injection**: Memory code injection
- **security_file_open**: File access monitoring
- **mem_prot_alert**: Memory protection alerts
