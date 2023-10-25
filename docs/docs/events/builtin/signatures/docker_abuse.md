
# Docker socket abuse detected

## Intro

The `DockerAbuse` signature is designed to identify malicious activities
targeting the Docker UNIX socket, specifically when this activity originates
from within a container.

This UNIX socket serves as the primary entry point for the Docker API. Malicious
actions against this socket can be indicative of an attempt to compromise the
host or the wider Docker environment.

## Description

Docker socket (`docker.sock`) represents a significant security boundary. When
this socket is accessed from within a container, it provides a potential pathway
for an attacker to execute commands directly on the host or on other containers.
This could lead to a wide range of malicious activities such as container
escape, launching of new containers, or even compromising the host system
itself.

## Purpose

This signature aims to protect Docker environments by detecting when the UNIX
socket is being abused. It is specifically tailored to identify the unauthorized
access or malicious activities against the Docker socket from within a
containerized environment.

## Metadata

- **ID**: TRC-1019
- **Version**: 1
- **Name**: Docker socket abuse detected
- **EventName**: docker_abuse
- **Description**: Monitors for any suspicious activities targeting the Docker UNIX socket from within a container, which may indicate an attempt to compromise the Docker environment or the host system.
- **Properties**:
  - **Severity**: 2
  - **Category**: privilege-escalation
  - **Technique**: Exploitation for Privilege Escalation
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--b21c3b2d-02e6-45b1-980b-e69051040839
  - **external_id**: T1068

## Findings

Upon detection of any malicious or suspicious activity, the signature returns a
`Finding` structure. The findings don't carry specific data fields related to
the event, apart from the metadata of the event itself.

## Events Used

This signature primarily responds to two event types:

1. `security_file_open` - Indicative of a file being opened. This event is
checked for access to the `docker.sock` file from within a container.
2. `security_socket_connect` - Indicates a connection attempt to a UNIX socket.
This event identifies if there's a connection to the Docker UNIX socket from
within a container.

By monitoring these events, the signature ensures comprehensive coverage against
potential Docker socket abuse.
