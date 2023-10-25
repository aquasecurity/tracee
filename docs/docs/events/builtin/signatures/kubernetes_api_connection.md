
# Kubernetes API server connection detected

## Intro

The `K8sApiConnection` signature detects attempts to connect to the Kubernetes
API server from within a container.

## Description

This signature tracks and monitors connections made from containers to the
Kubernetes API server. It maintains a mapping of container IDs and their
respective Kubernetes API server IP addresses.

When a connection to the tracked Kubernetes API server IP address is detected,
an alert is raised, as unauthorized access or communication attempts with the
Kubernetes API can signal potential security breaches.

## Purpose

The Kubernetes API server is the central management entity of a Kubernetes
cluster. Malicious attempts to communicate or interact with it can be indicative
of information gathering, credential extraction, or attempts to deploy malicious
containers. By detecting such connections, the system can identify unauthorized
or suspicious activities early on.

## Metadata

- **ID**: TRC-1013
- **Version**: 0.1.0
- **Name**: Kubernetes API server connection detected
- **EventName**: k8s_api_connection
- **Description**: Monitoring and alerting on connections to the Kubernetes API server, as interactions with the API server can reveal attempts to gather data, credentials or run malicious containers.
- **Tags**: container
- **Properties**:
  - **Severity**: 1
  - **MITRE ATT&CK**: Discovery: Cloud Service Discovery

## Findings

Upon detection, the signature returns a `Finding` data structure with the
following fields:

- **ip**: (Type: string) The IP address of the Kubernetes API server that the container tried to connect to.

## Events Used

The signature responds to two primary events:

1. `sched_process_exec` - Triggered when a process is scheduled for execution within a container. It checks for the Kubernetes API server IP in the container's environment variables.
2. `security_socket_connect` - Indicates when a socket connection is made within a container. If the connection IP matches the earlier stored Kubernetes API server IP, an alert is generated.
