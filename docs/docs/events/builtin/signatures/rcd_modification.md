
# Rcd Modification Detection

## Intro

The `RcdModification` signature identifies changes or modifications to the rcd
files and related commands. These files are crucial as they are scripts executed
during boot and runlevel switches. By altering these scripts, adversaries can
maintain persistence across system reboots.

## Description

The rcd (runlevel control directories) scripts are integral to the Linux system
as they are responsible for service control during system bootup and when the
system's runlevel changes. When these scripts or related directories are
altered, it can imply a persistent malicious foothold within the system.

This signature, `RcdModification`, monitors the rcd files and directories for
any modifications. By identifying unauthorized changes to these components, it
aims to counteract threats that rely on altering system initialization scripts
to ensure continuous malicious activity after system reboots.

## Purpose

The primary objective of this signature is to detect unauthorized changes or
executions related to the rcd files, directories, and commands. By doing so, it
aims to safeguard the system against threats that target bootup scripts for
persistence.

## Metadata

- **ID**: TRC-1026
- **Version**: 1
- **Name**: Rcd modification detected
- **EventName**: rcd_modification
- **Description**: The signature zeroes in on modifications to the rcd files. Since these files run during system bootup and runlevel switches, they are paramount for system initialization. Adversaries can modify or append to these files, ensuring their malicious code runs consistently even after reboots, thus achieving persistence.
- **Properties**:
  - **Severity**: 2 (Moderate threat level)
  - **Category**: persistence
  - **Technique**: RC Scripts
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--dca670cf-eeec-438f-8185-fd959d9ef211
  - **external_id**: T1037.004

## Findings

Upon detection of a potential threat, the signature reports back a `Finding` data structure, which encapsulates:

- **SigMetadata**: Information about the potential threat based on the signature's criteria.
- **Event**: The specifics of the event which caused the signature to trigger.
- **Data**: Currently set to `nil`, indicating that no additional data is provided.

## Events Used

This signature relies on several events:

- `security_file_open`: This event activates when a file is accessed. The signature checks if the file is one of the rcd files and if it's being written to.
- `security_inode_rename`: This event is triggered when an inode is renamed. The signature uses this event to discern if any rcd files or directories are being renamed.
- `sched_process_exec`: This event fires up when a new process is initiated. The signature ensures if the `update-rc.d` command, which manages the rcd scripts, is executed.
