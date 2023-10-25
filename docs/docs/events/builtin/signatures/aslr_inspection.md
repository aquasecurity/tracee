
# ASLR inspection detected

## Intro

The `AslrInspection` signature detects instances where the ASLR (address space
layout randomization) configuration is being read.

## Description

ASLR is a vital security mechanism used by Linux operating systems to randomize
the memory locations used by processes, making it more difficult to exploit
vulnerabilities that rely on predictable memory addresses.

However, adversaries may seek to inspect or even disable ASLR in their attempts
to exploit vulnerabilities. The signature specifically tracks attempts to open
and read the ASLR configuration from its standard location
(`/proc/sys/kernel/randomize_va_space`).

## Purpose

By alerting on instances where the ASLR configuration is being inspected, the
system can identify potential preparatory actions by adversaries who might be
gearing up for more direct attacks or exploit attempts. Disabling or altering
ASLR can be a crucial step in a larger attack plan.

## Metadata

- **ID**: TRC-109
- **Version**: 1
- **Name**: ASLR inspection detected
- **EventName**: aslr_inspection
- **Description**: Monitors for attempts to inspect the ASLR configuration on a Linux system, a potential precursor to privilege escalation attacks.
- **Properties**:
  - **Severity**: 0
  - **Category**: privilege-escalation
  - **Technique**: Exploitation for Privilege Escalation
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--b21c3b2d-02e6-45b1-980b-e69051040839
  - **external_id**: T1068

## Findings

Upon detection, the signature returns a `Finding` data structure, but it does
not contain any specific data fields related to the event, other than the
metadata of the event itself.

## Events Used

The signature is primarily triggered by the following event:

1. `security_file_open` - Indicates when a file is opened. The signature checks
if the file being opened matches the path of the ASLR configuration and if it's
being read.
