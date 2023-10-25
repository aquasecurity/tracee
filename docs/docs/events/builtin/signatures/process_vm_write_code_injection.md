
# Process VM Write Code Injection Detection

## Intro

The `ProcessVmWriteCodeInjection` signature is designed to detect potential code
injection attacks using the `process_vm_writev` syscall.

Code injection attacks involve injecting malicious code into another process's
memory. Such techniques allow adversaries to execute their malicious payloads
within the context of other processes, potentially evading detection and
benefiting from the permissions of the targeted process.

## Description

The `process_vm_writev` syscall allows one process to write into another
process's memory. While there are legitimate uses for this syscall, it can also
be abused for code injection purposes.

The `ProcessVmWriteCodeInjection` signature closely monitors this syscall for
indications of cross-process memory writes that might indicate malicious
activity.

## Purpose

The core purpose of the `ProcessVmWriteCodeInjection` signature is to provide
real-time detection and alerts when a process tries to write into another
process's memory using the `process_vm_writev` syscall. This is critical because
code injection can give attackers the ability to run arbitrary code with the
permissions of the compromised process, making it a dangerous attack vector.

## Metadata

- **ID**: TRC-1025
- **Version**: 1
- **Name**: Code injection detected using process_vm_writev syscall
- **EventName**: process_vm_write_inject
- **Description**: Detects possible code injection attempts into another process's memory. This technique is employed by adversaries to execute malicious code in the context of another process.
- **Properties**:
  - **Severity**: 3 (Moderate to high threat level)
  - **Category**: defense-evasion
  - **Technique**: Process Injection
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d
  - **external_id**: T1055

## Findings

If a potential code injection attempt is detected, the signature returns a
`Finding` data structure containing:

- **SigMetadata**: Metadata outlining the threat as per the signature's definition.
- **Event**: A detailed log of the specific event that triggered the detection.
- **Data**: Currently set to `nil`, implying that no additional data is accompanying the detection.

## Events Used

The primary event this signature monitors is:

- `process_vm_writev`: Invoked when the `process_vm_writev` syscall is used. The
signature verifies if the memory write is targeting another process's memory
(i.e., when the source and destination PIDs don't match). If such a discrepancy
is observed, it may be indicative of a code injection attempt.
