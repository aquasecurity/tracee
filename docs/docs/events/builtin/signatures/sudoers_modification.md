
# Sudoers File Modification Detection

## Intro

The `SudoersModification` signature is designed to detect unauthorized or
unexpected changes to the sudoers configuration files on a system.

The sudoers file is a critical part of Unix and Linux systems, controlling which
users can run which commands as superuser. Unauthorized changes to this file can
lead to privilege escalation and unauthorized command execution.

## Description

The sudoers file, traditionally located at `/etc/sudoers`, contains the rules
that users must follow when they use the `sudo` command. It dictates who can run
what, as whom, and from where. Any unauthorized changes to this file, or the
related configuration in `/etc/sudoers.d/`, could allow an attacker to elevate
their privileges and take control of a system.

## Purpose

The main aim of this signature is to monitor for modifications to the sudoers
configuration. By doing so, it helps in the early detection of possible security
breaches or misconfigurations which could jeopardize the security posture of a
system.

## Metadata

- **ID**: TRC-1028
- **Version**: 1
- **Name**: Sudoers file modification detected
- **EventName**: sudoers_modification
- **Description**: Monitors for unauthorized changes to the sudoers file. The sudoers file manages permissions for the `sudo` command. Unauthorized changes could allow an attacker to elevate privileges or run commands without proper authorization.
- **Properties**:
  - **Severity**: 2
  - **Category**: privilege-escalation
  - **Technique**: Sudo and Sudo Caching
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--1365fe3b-0f50-455d-b4da-266ce31c23b0
  - **external_id**: T1548.003

## Findings

On detecting a potential unauthorized modification to the sudoers configuration,
a `Finding` is generated. This `Finding` contains detailed information about the
event, along with associated threat metadata, enabling responders to take
appropriate action.

## Events Used

This signature is chiefly concerned with two events:

- `security_file_open`: Triggered when a file is accessed. The signature checks
if the file is being opened with write permissions.

- `security_inode_rename`: This event signifies the renaming of a file or
directory. Renaming critical files, like the sudoers file, might be an indicator
of malicious activity.

The signature checks if the path associated with these events matches the known
paths for sudoers files or starts with the directory paths designated for
sudoers configurations.
