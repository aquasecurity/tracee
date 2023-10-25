
# Kcore Memory File Read Detection

## Intro

The `ProcKcoreRead` signature identifies attempts to access and read the
`/proc/kcore` file, a crucial system file that mirrors the physical memory of
the Linux system.

## Description

The `/proc/kcore` file is a unique entity in Linux systems. It offers an image
of the physical memory in the ELF core dump file format. This means it provides
a comprehensive snapshot of the entire system's memory. While this can be useful
for certain legitimate debugging scenarios, malicious actors can also leverage
it to acquire a comprehensive memory dump, potentially containing sensitive
data, credentials, or other valuable information.

Reading the `/proc/kcore` file can be a significant step for adversaries aiming
for techniques such as container escapes. It's a tactic that can give them
detailed insights into the host system, which could be subsequently exploited
for more advanced attacks.

The `ProcKcoreRead` signature vigilantly watches for any attempts to read this
file and raises alerts if such activities are detected.

## Purpose

The central aim of this signature is to detect and raise alerts concerning
unauthorized access and reading of the `/proc/kcore` file. Monitoring this file
is vital since any unauthorized reads can be indicative of adversarial
intentions, such as gleaning host memory data for potential container escape
strategies.

## Metadata

- **ID**: TRC-1021
- **Version**: 1
- **Name**: Kcore memory file read
- **EventName**: proc_kcore_read
- **Description**: The signature tracks any read operations on the `/proc/kcore` file. This file provides a complete dump of the host's physical memory. Unauthorized access to it can suggest an attacker's attempts to gain insights into the host memory, potentially aiming for container escapes or other privilege escalation techniques.
- **Properties**:
  - **Severity**: 2 (Moderate to low threat level)
  - **Category**: privilege-escalation
  - **Technique**: Escape to Host
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665
  - **external_id**: T1611

## Findings

When a potential threat is pinpointed, the signature returns a `Finding` data
structure, which contains:

- **SigMetadata**: Metadata detailing the threat as per the signature's information.
- **Event**: The specific event details that instigated the signature's activation.
- **Data**: Currently set to `nil`, which denotes no additional data accompanies this structure.

## Events Used

The signature relies on the following event for its operations:

- `security_file_open`: Activates when a file is accessed. The signature
examines the accessed file's pathname and flags to determine if there's an
attempt to read the `/proc/kcore` file.
