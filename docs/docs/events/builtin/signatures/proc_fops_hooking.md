
# File Operations Hooking on Proc Filesystem Detection

## Intro

The `ProcFopsHooking` signature is constructed to detect malicious hooking of
file operations on the proc filesystem.

The proc filesystem serves as a pseudo-filesystem which presents running
processes as files. Rootkits and similar sophisticated malware can exploit this
system by replacing the default file operations, hence altering or gaining
control over how the OS interacts with its processes.

## Description

The proc filesystem offers an interface that maps running processes to files.
This mapping is crucial for utilities such as `ps` and `top`, which rely on this
representation to list and provide details of running processes.

File operations define how the system interacts with these 'files', and hooking
these operations can let an attacker gain unauthorized control over system
functions. For instance, they can influence file listings or even hijack
execution flows.

This kind of meddling is not just a hallmark of rootkits but is also an alarming
sign that the kernel could be compromised. Additionally, hidden modules,
signified as hidden symbol owners, amplify the threat as they may indicate a
deeper penetration of adversarial activities.

## Purpose

`ProcFopsHooking` is geared towards real-time detection of such malicious file
operation hooking on the proc filesystem. Recognizing these hooks can give a
critical headstart in responding to and neutralizing threats, preserving the
kernel's integrity and ensuring that system processes are left uncompromised.

## Metadata

- **ID**: TRC-1020
- **Version**: 1
- **Name**: File operations hooking on proc filesystem detected
- **EventName**: proc_fops_hooking
- **Description**: It monitors malicious hooking on the proc filesystem. Such hooking interferes with how processes, presented as files, are handled by the system. Malicious entities, like rootkits, can hijack or control system functions through this, implying the kernel may be compromised.
- **Properties**:
  - **Severity**: 3 (Moderate to high threat level)
  - **Category**: defense-evasion
  - **Technique**: Rootkit
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--0f20e3cb-245b-4a61-8a91-2d93f7cb0e9b
  - **external_id**: T1014

## Findings

Upon detecting malicious hooking, the signature generates a `Finding`, which
contains:

- **SigMetadata**: Metadata that offers insights into the detected threat based on the signature's defined parameters.
- **Event**: A comprehensive log detailing the event that prompted the detection.
- **Data**: This outlines the specific file operations on the proc filesystem that have been hooked, thus offering more granularity on the potential threat.

## Events Used

The signature mainly focuses on the event:

- `hooked_proc_fops`: Triggered when malicious hooking of proc filesystem file
operations is detected. The signature evaluates the data attached to this event
to determine the exact nature and extent of the hooking.
