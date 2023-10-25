
# System Request Key Configuration Modification Detection

## Intro

The `SystemRequestKeyConfigModification` signature detects modifications to the
System Request Key configuration files, which are powerful utilities that allow
direct kernel input.

## Description

The System Request Key (often abbreviated as SysRq) is a mechanism in the Linux
kernel that provides a way to send commands directly to the kernel via key
combinations.

These combinations allow, among other things, a user to perform various
low-level commands regardless of the system's state. Because of its potent
capabilities, any unauthorized or suspicious modifications to its configurations
could indicate adversarial activity.

Specifically, this signature focuses on detecting attempts to modify and
activate the System Request Key configuration files located at
`/proc/sys/kernel/sysrq` and `/proc/sysrq-trigger`.

## Purpose

The primary objective of this signature is to detect and flag any unauthorized
or suspicious modifications to the System Request Key configuration. Such
modifications could allow an adversary to immediately shut down or restart a
system. Moreover, if combined with read access to kernel logs, it might leak
sensitive host-related information, enabling potential container escape tactics.

## Metadata

- **ID**: TRC-1031
- **Version**: 1
- **Name**: System request key configuration modification
- **EventName**: system_request_key_mod
- **Description**: The signature detects modifications to the System Request Key configuration files. Unauthorized or malicious alterations to these files can grant the ability to shut down or restart systems and disclose host-related data that can potentially be used for container escapes.
- **Properties**:
  - **Severity**: 3 (Moderate threat level)
  - **Category**: privilege-escalation
  - **Technique**: Escape to Host
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665
  - **external_id**: T1611

## Findings

Upon detecting a potential threat, the signature returns a `Finding` data
structure, comprising:

- **SigMetadata**: Metadata about the threat based on the signature.
- **Event**: Details of the event that caused the signature to trigger.
- **Data**: Currently set to `nil`, meaning no extra information is provided in this structure.

## Events Used

The signature is contingent on the following events:

- `security_file_open`: Activated when a file is accessed. The signature
examines the accessed file's pathname and flags to determine if the System
Request Key configuration files are being modified.
