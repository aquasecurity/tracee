---
title: TRACEE-ASLR-INSPECTION
section: 1
header: Tracee Event Manual
---

## NAME

**aslr_inspection** - ASLR inspection detection signature

## DESCRIPTION

The **aslr_inspection** signature detects instances where the ASLR (address space layout randomization) configuration is being read. ASLR is a vital security mechanism used by Linux operating systems to randomize the memory locations used by processes, making it more difficult to exploit vulnerabilities that rely on predictable memory addresses.

However, adversaries may seek to inspect or even disable ASLR in their attempts to exploit vulnerabilities. The signature specifically tracks attempts to open and read the ASLR configuration from its standard location (`/proc/sys/kernel/randomize_va_space`).

By alerting on instances where the ASLR configuration is being inspected, the system can identify potential preparatory actions by adversaries who might be gearing up for more direct attacks or exploit attempts. Disabling or altering ASLR can be a crucial step in a larger attack plan.

## SIGNATURE METADATA

- **ID**: TRC-109
- **Version**: 1
- **Severity**: 0 (Low)
- **Category**: privilege-escalation
- **Technique**: Exploitation for Privilege Escalation
- **MITRE ATT&CK**: T1068

## EVENT SETS

**signatures**, **security_alert**

## DATA FIELDS

Upon detection, the signature returns a Finding data structure with metadata about the event, but no specific additional data fields.

## DEPENDENCIES

**Events Used:**

- security_file_open: Indicates when a file is opened. The signature checks if the file being opened matches the path of the ASLR configuration and if it's being read

## USE CASES

- **Privilege Escalation Detection**: Monitor for attempts to inspect ASLR configuration as a potential precursor to privilege escalation attacks

- **Attack Preparation Monitoring**: Identify adversaries gathering system information before launching exploits

- **Security Reconnaissance**: Detect reconnaissance activities targeting system security mechanisms

## RELATED EVENTS

- **security_file_open**: File opening security events