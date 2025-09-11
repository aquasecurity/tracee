---
title: TRACEE-SECURITY-SOCKET-CONNECT
section: 1
header: Tracee Event Manual
---

## NAME

**security_socket_connect** - socket connection security check

## DESCRIPTION

Triggered when a socket attempts to establish a connection through the Linux Security Module (LSM) hook. This event captures information about the socket and the remote address it's trying to connect to, providing visibility into outbound network communications.

The event monitors socket connections for security, diagnostics, and compliance purposes by hooking into the kernel's `security_socket_connect` function.

## EVENT SETS

**none**

## DATA FIELDS

**sockfd** (*int32*)
: The file descriptor referring to the socket attempting the connection

**remote_addr** (*trace.SockAddr*)
: The remote address structure containing connection destination details. Depending on the address family (IPv4, IPv6, or UNIX), this contains different address information

## DEPENDENCIES

**LSM Hook:**

- security_socket_connect (required): LSM hook for socket connection security checks

## USE CASES

- **Security monitoring**: Track outbound connections to detect malicious communications

- **Network auditing**: Monitor connections for compliance and security policies

- **Incident response**: Investigate suspicious network connections during security incidents

- **Application debugging**: Diagnose network connectivity issues in applications

- **Traffic analysis**: Understand application network communication patterns

## ADDRESS FAMILIES

The `remote_addr` field can contain different address types:

- **IPv4**: `sockaddr_in` structure with IP address and port
- **IPv6**: `sockaddr_in6` structure with IPv6 address and port
- **UNIX**: `sockaddr_un` structure with socket path

## PERFORMANCE CONSIDERATIONS

Monitoring every socket connection may introduce overhead in systems with frequent network communications. Consider filtering or adjusting monitoring scope for high-throughput environments.

## RELATED EVENTS

- **security_socket_create**: Socket creation security events
- **security_socket_listen**: Socket listen security events
- **security_socket_accept**: Socket accept security events
- **security_socket_bind**: Socket bind security events
- **security_socket_setsockopt**: Socket option security events
- **connect**: Connect system call events