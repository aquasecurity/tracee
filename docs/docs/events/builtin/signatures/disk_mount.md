
# Container Device Mount Detection

## Intro

The `DiskMount` signature aims to identify instances when a container mounts a
host device filesystem. Such actions, while sometimes valid, can be indicative
of malicious activity, as they might be exploited by attackers attempting to
break out of the container and gain unauthorized access to the host machine.

## Description

Containers are isolated environments, and attempts to mount the host device
filesystem within them can be suspicious.

The `DiskMount` signature observes the `security_sb_mount` event, particularly
in a container context, to detect and evaluate such operations. If the mounted
device pertains to the host, as indicated by its presence in the `/dev/`
directory, an alert is generated.

## Purpose

The primary objective of the `DiskMount` signature is to deliver real-time
alerts for potential malicious activity involving the mounting of host device
filesystems in containers. This is essential as container escape techniques
could grant attackers enhanced privileges, putting the security and integrity of
the host system at risk.

## Metadata

- **ID**: TRC-1014
- **Version**: 1
- **Name**: Container device mount detected
- **EventName**: disk_mount
- **Description**: Monitors containers for mounting host device filesystems, potentially indicative of malicious attempts at container escape.
- **Properties**:
  - **Severity**: 3 (Moderate to high threat level)
  - **Category**: privilege-escalation
  - **Technique**: Escape to Host
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665
  - **external_id**: T1611

## Findings

Upon the identification of a potentially harmful device mount operation:

- **SigMetadata**: Provides a detailed view of the threat according to the signature's specifications.
- **Event**: Captures a comprehensive log of the specific occurrence that instigated the alert.
- **Data**: Currently marked as `nil`, suggesting no supplementary data is paired with the detection.

## Events Used

The signature exclusively tracks:

- `security_sb_mount`: Triggered during a filesystem mount operation.
