
# Cgroups notify_on_release file modification

## Intro

The `CgroupNotifyOnReleaseModification` signature identifies modifications to
the `notify_on_release` file within Cgroups. Unauthorized or unintended changes
to this file may suggest attempts to escape from a container or to exploit the
Cgroups feature for malicious purposes.

## Description

Cgroups (Control Groups) is a Linux kernel feature that limits, accounts for,
and isolates the resource usage (CPU, memory, disk I/O, etc.) of a collection of
processes. The `notify_on_release` file within Cgroups specifies if a
notification should be sent when the resources of the Cgroup are no longer in
use.

Manipulating this file could allow adversaries to be notified when a
containerized process completes, potentially giving them an opportunity to
exploit the released resources. This may enable unauthorized actions, like
container escape or privilege escalation.

## Purpose

The main goal of this signature is to detect and raise alerts on unauthorized or
suspicious modifications to the `notify_on_release` file within Cgroups. By
monitoring such changes, this signature aids in the early detection and
prevention of potential container escape attempts or other malicious activities
leveraging Cgroup mechanisms.

## Metadata

- **ID**: TRC-106
- **Version**: 1
- **Name**: Cgroups notify_on_release file modification
- **EventName**: cgroup_notify_on_release
- **Description**: Monitors for attempts to modify the `notify_on_release` file in Cgroups. Unauthorized changes might hint at adversarial efforts to exploit Cgroup functionalities, like trying to escape from containers.
- **Properties**:
  - **Severity**: 3
  - **Category**: privilege-escalation
  - **Technique**: Escape to Host
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665
  - **external_id**: T1611

## Findings

On detection of unauthorized or suspicious activities related to the
`notify_on_release` file, the signature produces a `Finding` which contains
details about the event and the associated threat metadata.

## Events Used

The signature primarily listens to the `security_file_open` event, especially
from the `container` origin. This event provides insights into attempts to
access or modify files, and in this context, specifically watches for
interactions with the `notify_on_release` file in Cgroups.
