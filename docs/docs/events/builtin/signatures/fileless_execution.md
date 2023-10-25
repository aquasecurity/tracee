
# Fileless Execution Detection

## Intro

The `FilelessExecution` signature is crafted to detect instances of fileless
execution, which involves running processes directly from memory rather than
from a file on the file system. Adversaries use such techniques to escape
detection, as fileless operations don't leave traditional footprints on the
disk.

## Description

Fileless execution is a sophisticated technique that circumvents traditional
security mechanisms which focus on files. By running processes directly from
memory, malicious actors can potentially operate undetected, as no file
artifacts are created on the storage system.

The `FilelessExecution` signature identifies these fileless execution attempts
by monitoring the `sched_process_exec` event. If it detects the process is
originating from a memory location rather than a file, an alert is raised.

## Purpose

The main goal of the `FilelessExecution` signature is to provide real-time
detection and alerts for fileless execution attempts. With an increasing number
of threats leveraging fileless techniques for stealth, being able to detect such
activities is crucial for maintaining a robust security posture.

## Metadata

- **ID**: TRC-105
- **Version**: 1
- **Name**: Fileless execution detected
- **EventName**: fileless_execution
- **Description**: Fileless execution was detected. Executing a process from memory instead from a file in the filesystem may indicate that an adversary is trying to avoid execution detection.
- **Properties**:
  - **Severity**: 3 (Moderate to high threat level)
  - **Category**: defense-evasion
  - **Technique**: Reflective Code Loading
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--4933e63b-9b77-476e-ab29-761bc5b7d15a
  - **external_id**: T1620

## Findings

Upon detecting a potential fileless execution, the signature produces a
`Finding` data structure comprising:

- **SigMetadata**: Metadata detailing the threat based on the signature's specifications.
- **Event**: A comprehensive log of the specific event that prompted the detection.
- **Data**: Currently set to `nil`, signifying that no supplementary data supports the detection.

## Events Used

The signature predominantly monitors the following event:

- `sched_process_exec`: This event is triggered when there's an attempt to
execute a process. The signature checks if the process's origin is a memory
path, hinting at a fileless execution attempt.
