---
title: TRACEE-K8S-CERT-THEFT
section: 1
header: Tracee Event Manual
---

## NAME

**k8s_cert_theft** - detect Kubernetes TLS certificate theft attempts

## DESCRIPTION

This event detects unauthorized access or potential theft of Kubernetes Transport Layer Security (TLS) certificates. These certificates are critical for secure communication between Kubernetes components, and their compromise could allow attackers to impersonate legitimate cluster components.

The event monitors both direct file access and rename operations involving Kubernetes certificate files, helping detect various exfiltration techniques. It also verifies that only authorized processes access these sensitive files.

## SIGNATURE METADATA

- **ID**: TRC-1018
- **Version**: 1
- **Severity**: 3
- **Category**: credential-access
- **Technique**: Steal Application Access Token
- **MITRE ID**: attack-pattern--890c9858-598c-401d-a4d5-c67ebcdd703a
- **MITRE External ID**: T1528

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying security events:

**pathname** (*string*)
: Path to the certificate file being accessed

**flags** (*string*)
: File access flags indicating the type of operation

**old_path** (*string*)
: Original path in case of rename operations

**new_path** (*string*)
: New path in case of rename operations

## DEPENDENCIES

- `security_file_open`: Monitor certificate file access
- `security_inode_rename`: Track certificate file renames

## USE CASES

- **Certificate protection**: Monitor sensitive TLS file access

- **Credential theft detection**: Identify unauthorized access attempts

- **Cluster security**: Protect component authentication

- **Incident response**: Track potential certificate compromise

## KUBERNETES CERTIFICATES

Critical certificate types:

- API server certificates
- Kubelet client certificates
- Service account tokens
- etcd client certificates
- Controller manager certificates
- Scheduler certificates

## ATTACK VECTORS

Common malicious uses include:

- **Component impersonation**: Masquerade as legitimate services
- **Man-in-the-middle**: Intercept cluster communications
- **Credential theft**: Access to cluster authentication
- **Lateral movement**: Cross-namespace access

## RISK ASSESSMENT

Risk factors to consider:

- **Cluster-wide Impact**: Affects all communications
- **Authentication Bypass**: Enables impersonation
- **Long-term Access**: Valid until certificate expiry
- **Detection Evasion**: Legitimate-looking traffic

## MITIGATION

Recommended security controls:

- Certificate rotation
- File permissions hardening
- Process isolation
- Access auditing
- Certificate pinning
- Network segmentation

## LEGITIMATE USES

Valid certificate access patterns:

- Kubernetes components
- Certificate managers
- Backup processes
- Monitoring agents

## RELATED EVENTS

- **security_file_open**: File access monitoring
- **security_inode_rename**: File rename operations
- **k8s_api_connection**: API server connections
- **container_create**: Container lifecycle events
