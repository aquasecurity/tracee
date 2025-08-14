---
title: TRACEE-CORE-PATTERN-MODIFICATION
section: 1
header: Tracee Event Manual
---

## NAME

**core_pattern_modification** - detect modifications to core dump configuration

## DESCRIPTION

This event detects unauthorized changes to the core dump configuration file (`/proc/sys/kernel/core_pattern`). The core_pattern file controls how the Linux kernel handles core dumps when programs crash, including where the dumps are stored and what program processes them.

Modifications to this file are security-sensitive because the core_pattern can specify an executable to process core dumps, potentially allowing attackers to execute arbitrary commands with elevated privileges when programs crash.

## SIGNATURE METADATA

- **ID**: TRC-1011
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
: Path to the core_pattern file being accessed

**flags** (*string*)
: File access flags indicating the type of operation

## DEPENDENCIES

- `security_file_open`: Monitor file access attempts to core_pattern

## USE CASES

- **Container security**: Detect potential container escape attempts

- **Privilege escalation detection**: Monitor for unauthorized command execution setup

- **System integrity**: Track changes to critical kernel configurations

- **Incident response**: Identify attempts to exploit core dump handling

## CORE PATTERN SECURITY

Critical aspects of core_pattern:

- Controls system-wide core dump handling
- Can specify arbitrary executables
- Runs with elevated privileges
- Affects all processes on the system

## ATTACK VECTORS

Common malicious modifications include:

- **Command injection**: Setting malicious executables as handlers
- **Container escape**: Breaking container isolation via core dumps
- **Privilege escalation**: Executing commands with elevated privileges
- **Information disclosure**: Capturing sensitive memory contents

## RISK ASSESSMENT

Risk factors to consider:

- **High Impact**: System-wide effect on core dump handling
- **Root Access**: Core dump handlers run with elevated privileges
- **Automated Execution**: Triggers on any program crash
- **Persistence**: Changes persist until system reboot

## MITIGATION

Recommended security controls:

- Restrict access to /proc/sys/kernel/
- Monitor core_pattern modifications
- Use seccomp to control core dumps
- Implement proper container isolation

## RELATED EVENTS

- **security_file_open**: File access monitoring
- **process_execute**: Track execution of core dump handlers
- **security_bprm_check**: Binary execution security checks
- **container_create**: Container lifecycle events
