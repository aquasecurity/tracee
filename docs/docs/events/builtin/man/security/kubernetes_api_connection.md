---
title: TRACEE-K8S-API-CONNECTION
section: 1
header: Tracee Event Manual
---

## NAME

**k8s_api_connection** - detect container connections to Kubernetes API server

## DESCRIPTION

This event detects attempts by containers to connect to the Kubernetes API server. The Kubernetes API server is the control plane component that exposes the Kubernetes API, making it a critical security boundary. Unauthorized access attempts could indicate reconnaissance, credential theft, or attempts to deploy malicious workloads.

The event maintains a mapping of container IDs to their respective Kubernetes API server IP addresses and monitors for connection attempts to these addresses, providing early warning of potential security breaches.

## SIGNATURE METADATA

- **ID**: TRC-1013
- **Version**: 0.1.0
- **Severity**: 1
- **Category**: Discovery
- **Technique**: Cloud Service Discovery
- **Tags**: container

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

**ip** (*string*)
: The IP address of the Kubernetes API server being accessed

**container_id** (*string*)
: ID of the container making the connection

**comm** (*string*)
: Name of the process attempting the connection

**port** (*uint32*)
: Destination port of the connection

## DEPENDENCIES

- `sched_process_exec`: Track process execution in containers
- `security_socket_connect`: Monitor socket connections

## USE CASES

- **Access control**: Monitor unauthorized API access

- **Container security**: Detect container escape attempts

- **Privilege escalation**: Identify unauthorized API interactions

- **Reconnaissance detection**: Spot information gathering attempts

## KUBERNETES SECURITY

Critical security aspects:

- API server is the cluster control plane
- Manages all cluster operations
- Handles authentication and authorization
- Stores sensitive cluster data

## ATTACK VECTORS

Common malicious uses include:

- **Information gathering**: Enumerate cluster resources
- **Credential theft**: Access service account tokens
- **Workload deployment**: Launch malicious pods
- **Lateral movement**: Access other namespaces

## RISK ASSESSMENT

Risk factors to consider:

- **Cluster Control**: Full API access possible
- **Sensitive Data**: Access to secrets
- **Cross-namespace**: Potential blast radius
- **Persistence**: Ability to create workloads

## LEGITIMATE USES

Valid API access scenarios:

- Service mesh sidecars
- Monitoring agents
- Operators and controllers
- CI/CD tools

## MITIGATION

Recommended security controls:

- Network policies
- RBAC restrictions
- Service account limits
- API server audit logging
- Pod security standards

## RELATED EVENTS

- **security_socket_connect**: Network connections
- **sched_process_exec**: Process execution
- **container_create**: Container lifecycle
- **k8s_cert_theft**: Certificate theft attempts
