---
title: TRACEE-SECURITY-SOCKET-BIND
section: 1
header: Tracee Event Manual
---

## NAME

**security_socket_bind** - socket bind operation security check

## DESCRIPTION

Triggered when a socket is bound to a local address and port through the Linux Security Module (LSM) hook. This event captures socket binding operations, which are crucial for setting up servers, defining source addresses for outgoing connections, and establishing network services.

Socket binding is a fundamental networking operation where applications specify which local address and port they want to use for network communication. Monitoring these operations provides visibility into service initialization and network configuration changes.

## EVENT SETS

**none**

## DATA FIELDS

**sockfd** (*int32*)
: The file descriptor referring to the socket being bound

**local_addr** (*trace.SockAddr*)
: The local address structure containing the address and port details for the binding operation

## DEPENDENCIES

**LSM Hook:**

- security_socket_bind (required): LSM hook for socket bind security checks

## USE CASES

- **Service monitoring**: Track when network services are started or reconfigured

- **Security auditing**: Detect unauthorized service bindings or port usage

- **Network configuration**: Monitor network service setup and port allocation

- **Incident response**: Investigate unexpected network service activity

- **Compliance monitoring**: Ensure network services comply with policies

## BINDING SCENARIOS

Common socket binding scenarios:

- **Server initialization**: Web servers, database servers binding to listening ports
- **Service discovery**: Applications binding to well-known ports
- **Dynamic port allocation**: Applications requesting any available port (port 0)
- **Specific interface binding**: Binding to specific network interfaces
- **Privilege port binding**: Binding to ports below 1024 (requires privileges)

## ADDRESS FAMILIES

The `local_addr` field contains different address types:

- **IPv4**: `sockaddr_in` with IPv4 address and port
- **IPv6**: `sockaddr_in6` with IPv6 address and port
- **UNIX**: `sockaddr_un` with filesystem socket path

## SECURITY CONSIDERATIONS

Monitor for suspicious binding patterns:

- **Privilege escalation**: Unauthorized binding to privileged ports
- **Service hijacking**: Binding to ports used by other services
- **Backdoor services**: Unexpected services binding to unusual ports
- **Network reconnaissance**: Applications probing port availability

## PORT CATEGORIES

- **Well-known ports (0-1023)**: Require root privileges to bind
- **Registered ports (1024-49151)**: Commonly used application ports
- **Dynamic/private ports (49152-65535)**: Typically used for client connections

## PERFORMANCE CONSIDERATIONS

Socket binding events are relatively infrequent compared to data transfer operations, but can be numerous in environments with frequent service starts/stops or applications that create many sockets.

## RELATED EVENTS

- **security_socket_create**: Socket creation security events
- **security_socket_listen**: Socket listen security events
- **security_socket_accept**: Socket accept security events
- **security_socket_connect**: Socket connect security events
- **bind**: Bind system call events