
# Illegitimate Shell Detection

## Intro

The `IllegitimateShell` signature is specifically designed to detect instances
where a web server program spawns a shell. In a standard operating environment,
web servers seldom run shell programs. When observed, this behavior might
signify a malicious actor exploiting a web server, aiming for command-line
execution on the server.

## Description

Web servers primarily serve content and rarely require a shell to function. When
a shell gets spawned by a web server, it's often a strong indication of
compromise. The `IllegitimateShell` signature works by monitoring for the
`security_bprm_check` event and examining if any of the predefined web server
processes initiate shell execution.

## Purpose

The principal aim of the `IllegitimateShell` signature is to offer real-time
alerts and detection for situations where web servers improperly initiate shell
processes. Recognizing such anomalies swiftly is paramount in identifying
potential breaches, facilitating immediate action and mitigation.

## Metadata

- **ID**: TRC-1016
- **Version**: 1
- **Name**: Web server spawned a shell
- **EventName**: illegitimate_shell
- **Description**: A web-server program on your server spawned a shell program. Shells are command-line tools, and it's unconventional for web servers to initiate them. This alert might point to a malicious actor leveraging a web server to execute commands on the server.
- **Properties**:
  - **Severity**: 2 (Moderate threat level)
  - **Category**: initial-access
  - **Technique**: Exploit Public-Facing Application
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c
  - **external_id**: T1190

## Findings

When an illegitimate shell gets detected from a web server process, the
signature formulates a `Finding` data structure which consists of:

- **SigMetadata**: Metadata that provides insightful details about the potential threat as per the signature's guidelines.
- **Event**: An extensive record of the event that set off the detection.
- **Data**: Currently marked as `nil`, indicating there's no additional data underpinning the detection.

## Events Used

The signature primarily keeps an eye on the subsequent event:

- `security_bprm_check`: Triggered when there's an attempt to execute a program.
The signature inspects if the web server processes are trying to run any of the
listed shell names.
