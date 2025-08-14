---
title: TRACEE-DOCKER-ABUSE
section: 1
header: Tracee Event Manual
---

## NAME

**docker_abuse** - Docker socket abuse detection

## DESCRIPTION

Triggered when malicious activities targeting the Docker UNIX socket are detected, specifically when originating from within a container. The Docker socket serves as the primary entry point for the Docker API, and unauthorized access can enable container escape, host compromise, and unauthorized container management.

Docker socket abuse represents a critical security risk as it provides a potential pathway for attackers to execute commands directly on the host system or manipulate other containers, effectively breaking container isolation boundaries.

This signature is useful for:

- **Container escape detection**: Identify attempts to break out of container isolation
- **Privilege escalation monitoring**: Detect unauthorized access to host resources
- **Docker security**: Monitor for Docker API abuse and unauthorized container operations

## SIGNATURE METADATA

- **ID**: TRC-1019
- **Version**: 1
- **Severity**: 2 (Moderate threat level)
- **Category**: privilege-escalation
- **Technique**: Exploitation for Privilege Escalation
- **MITRE ATT&CK**: T1068

## EVENT SETS

**signatures**, **privilege_escalation**

## DATA FIELDS

**access_info** (*object*)
: Information about the Docker socket access attempt

**container_context** (*object*)
: Context information about the container attempting access

## DEPENDENCIES

**System Events:**

- security_file_open (required): Monitors file access to detect docker.sock file access
- security_socket_connect (required): Monitors socket connections to detect Docker UNIX socket connections

## DETECTION LOGIC

The signature monitors for:

1. **File access events** to docker.sock from within containers
2. **Socket connection events** to Docker UNIX socket from containers
3. **Container context verification** to ensure detection only applies to containerized processes

## USE CASES

- **Container security**: Prevent unauthorized container escape attempts

- **Docker environment protection**: Secure Docker deployments against socket abuse

- **Incident response**: Investigate container-based attacks and privilege escalation

- **Compliance monitoring**: Ensure containers don't have unauthorized host access

- **Security auditing**: Monitor for violations of container isolation principles

## ATTACK SCENARIOS

Docker socket abuse enables:

- **Container escape**: Breaking out of container isolation to access host
- **Privilege escalation**: Gaining root access on the host system
- **Lateral movement**: Accessing other containers and their data
- **Host manipulation**: Installing malware or backdoors on the host
- **Resource abuse**: Creating unauthorized containers for cryptomining or other malicious purposes

## SOCKET ACCESS METHODS

Attackers may access Docker socket through:

- **Volume mounts**: Mounting `/var/run/docker.sock` into containers
- **Direct file access**: Attempting to read/write the socket file
- **Socket connections**: Connecting to the UNIX socket endpoint
- **API calls**: Using Docker API commands through the socket

## COMMON EXPLOITATION TECHNIQUES

- **Privileged container creation**: Creating containers with privileged access
- **Host filesystem access**: Mounting host directories into containers
- **Container inspection**: Enumerating existing containers and their configurations
- **Image manipulation**: Pulling malicious images or modifying existing ones
- **Network manipulation**: Modifying container network configurations

## PREVENTION STRATEGIES

- **Socket access control**: Restrict docker.sock access using file permissions
- **User namespaces**: Use user namespace remapping to limit container privileges
- **Rootless Docker**: Run Docker daemon in rootless mode when possible
- **SELinux/AppArmor**: Use mandatory access controls to restrict socket access
- **Container runtime security**: Use security-focused container runtimes

## LEGITIMATE USE CASES

Some legitimate scenarios may trigger this detection:

- **CI/CD pipelines**: Build systems that need Docker access
- **Container orchestration**: Tools like Kubernetes accessing Docker API
- **Monitoring tools**: System monitoring that requires container inspection
- **Development tools**: Docker-in-Docker scenarios for development

## RELATED EVENTS

- **security_file_open**: Primary detection for docker.sock file access
- **security_socket_connect**: Primary detection for socket connections
- **container_create**: Container creation events for context
- **container_remove**: Container removal events for analysis