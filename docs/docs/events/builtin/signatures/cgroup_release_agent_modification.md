
# Cgroups Release Agent File Modification Detection

## Intro

The `CgroupReleaseAgentModification` signature detects modifications to the
Cgroup release agent file, a critical file related to the resource management of
process groups in Linux.

## Description

Cgroups (short for "control groups") is a Linux kernel feature that provides a
mechanism for managing and monitoring system resources like CPU, memory, disk
I/O, and network usage by grouping a set of tasks (like processes and threads).

One of its key features is the `release_agent` which specifies a script or
command to be run whenever a cgroup becomes empty. Any unauthorized or malicious
modification to this file could be indicative of adversarial intent.

This signature specifically identifies attempts to modify the `release_agent`
file. Unauthorized changes to this file could be employed by adversaries in
techniques aiming for container escapes or other privilege escalation schemes.

## Purpose

The main purpose of this signature is to detect and raise alerts for
unauthorized modifications to the `release_agent` file of Cgroups. Since the
`release_agent` can be exploited by attackers to run arbitrary commands when
cgroups are empty, monitoring its changes is pivotal for ensuring system
security and container boundaries.

## Metadata

- **ID**: TRC-1010
- **Version**: 1
- **Name**: Cgroups release agent file modification
- **EventName**: cgroup_release_agent
- **Description**: The signature monitors the modification of the Cgroup release agent file. Unauthorized changes to this file may be indicative of an adversary trying to leverage Cgroup features for privilege escalation or container escaping techniques.
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
- **Event**: Specifics of the event that instigated the signature to activate.
- **Data**: Presently set to `nil`, signifying that no supplementary data is returned with this structure.

## Events Used

The signature is contingent on the following events:

- `security_file_open`: Triggers when a file is accessed. The signature inspects the accessed file's pathname and flags to ascertain if the `release_agent` file is being modified.
- `security_inode_rename`: Activates when there's an inode rename event. This is employed to identify if the `release_agent` is being renamed, which could be a tactic to hide malicious modifications.
