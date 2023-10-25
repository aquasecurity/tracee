
# Kubernetes TLS Certificate Theft Detection

## Intro

The `KubernetesCertificateTheftAttempt` signature is designed to detect
unauthorized access or potential theft of Kubernetes Transport Layer Security
(TLS) certificates. Kubernetes relies on TLS certificates for secure
communication between its components. Any unauthorized access or movement of
these certificates can potentially allow an adversary to impersonate Kubernetes
components within the cluster, jeopardizing its security.

## Description

TLS certificates are foundational to establishing trust between systems.
Kubernetes uses these certificates to ensure secure communication pathways
between different components, such as the kubelet scheduler, controller, and the
API Server. The theft or misuse of these certificates can give adversaries undue
access or the ability to masquerade as legitimate Kubernetes components.

The `KubernetesCertificateTheftAttempt` signature vigilantly monitors file
access patterns and renaming activities in the Kubernetes certificate directory
to catch any unauthorized or suspicious activities.

## Purpose

The primary aim of the `KubernetesCertificateTheftAttempt` signature is to
ensure real-time detection of unauthorized access to Kubernetes TLS
certificates. By proactively identifying potential theft or misuse, security
teams can promptly respond to contain the breach and safeguard the cluster.

## Metadata

- **ID**: TRC-1018
- **Version**: 1
- **Name**: K8s TLS certificate theft detected
- **EventName**: k8s_cert_theft
- **Description**: Theft of Kubernetes TLS certificates was recognized. These certificates play a pivotal role in establishing trust and secure communication within the Kubernetes cluster. If compromised, adversaries can impersonate legitimate Kubernetes components.
- **Properties**:
  - **Severity**: 3 (Moderate to high threat level)
  - **Category**: credential-access
  - **Technique**: Steal Application Access Token
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--890c9858-598c-401d-a4d5-c67ebcdd703a
  - **external_id**: T1528

## Findings

When a potential unauthorized access to Kubernetes TLS certificates is detected,
the signature generates a `Finding` data structure, encompassing:

- **SigMetadata**: Metadata detailing the perceived threat as per the signature's specifications.
- **Event**: A detailed log of the event that triggered the detection.
- **Data**: Presently marked as `nil`, indicating that there isn't any additional data supporting the detection.

## Events Used

The signature primarily monitors the following events:

- `security_file_open`: This event is triggered when there's an attempt to open
a file. The signature inspects if the operation pertains to reading and if the
file path aligns with Kubernetes certificates. It also ensures that only
legitimate processes can access the certificates.
- `security_inode_rename`: Engaged when there's a renaming activity within the
inode. The signature checks if the old path of the renamed item corresponds with
the Kubernetes certificate directory.
