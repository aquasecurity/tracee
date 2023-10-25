
# Code injection detected through procfs mem file

## Intro

The `ProcMemCodeInjection` signature detects attempts to inject code into
another process by writing to the `/proc/<pid>/mem` file.

## Description

The `/proc/<pid>/mem` file on Linux systems allows direct access to the memory
of a process, represented by the `<pid>` placeholder in the file path.

Adversaries might attempt to write malicious code into a process's memory space
by using this file, a tactic commonly referred to as code injection. Successful
code injection can allow adversaries to execute arbitrary code in the context of
another process, facilitating evasion, persistence, and potentially privilege
escalation.

## Purpose

By monitoring writes to the `/proc/<pid>/mem` file, this signature aims to
identify and alert on possible code injection attempts. Detecting such attempts
can be crucial for identifying and mitigating advanced threats that utilize
in-memory exploitation techniques.

## Metadata

- **ID**: TRC-1024
- **Version**: 1
- **Name**: Code injection detected through /proc/<pid>/mem file
- **EventName**: proc_mem_code_injection
- **Description**: Monitors for potential code injection attempts into another process using the `/proc/<pid>/mem` file, a technique that can be used to execute arbitrary code within the context of another process.
- **Properties**:
  - **Severity**: 3
  - **Category**: defense-evasion
  - **Technique**: Proc Memory
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--d201d4cc-214d-4a74-a1ba-b3fa09fd4591
  - **external_id**: T1055.009

## Findings

Upon detection, the signature returns a `Finding` data structure. The findings
don't contain any specific data fields related to the event, other than the
metadata of the event itself.

## Events Used

The signature primarily reacts to the following event:

1. `security_file_open` - Indicates when a file is opened. The signature checks
if the file being opened matches the pattern `/proc/<pid>/mem` and if it's being
written to.
