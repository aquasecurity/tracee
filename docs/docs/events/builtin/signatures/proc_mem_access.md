
# Process Memory Access Detection

## Intro

The `ProcMemAccess` signature is designed to monitor and identify unauthorized
or suspicious attempts to access a process's memory through the Linux proc
filesystem.

## Description

In Linux, each process has an associated directory in the `/proc` filesystem,
labeled by its PID (Process Identifier). Within this directory, the `mem` file
provides an interface to access the process's memory. This can be invaluable for
debugging, but it also poses a significant security risk. Malicious actors can
exploit this access point to read confidential data from running processes,
including secrets and credentials.

By accessing these memory files, adversaries can gain insights into the system's
operations and potentially extract valuable information. The `ProcMemAccess`
signature, therefore, employs a regex pattern to vigilantly track access to
these `mem` files, raising alerts when detected.

## Purpose

The primary objective of the `ProcMemAccess` signature is to flag unauthorized
or unexpected access to the memory of running processes. Monitoring these
accesses is paramount as it can provide early warnings about potential data
breaches or malware activities attempting to steal sensitive information.

## Metadata

- **ID**: TRC-1023
- **Version**: 1
- **Name**: Process memory access detected
- **EventName**: proc_mem_access
- **Description**: The signature identifies unauthorized or suspicious attempts to access the memory of running processes via the `/proc` filesystem. Such access can be indicative of attacks aiming to steal credentials, secrets, or other sensitive data from these processes.
- **Properties**:
  - **Severity**: 3 (Moderate threat level)
  - **Category**: credential-access
  - **Technique**: Proc Filesystem
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--3120b9fa-23b8-4500-ae73-09494f607b7d
  - **external_id**: T1003.007

## Findings

Upon detection of a potential threat, the signature returns a `Finding` data structure, which encapsulates:

- **SigMetadata**: Metadata, as defined by the signature, that outlines the specifics of the threat.
- **Event**: Detailed account of the event that triggered the signature.
- **Data**: Currently initialized to `nil`, signifying no supplementary data is attached.

## Events Used

The primary event the signature leans on for its functioning is:

- `security_file_open`: This event is triggered when there's an attempt to
access a file. The signature cross-references the accessed file's pathname with
its regex pattern to discern whether there's an endeavor to access a process's
memory file in the `/proc` filesystem.
