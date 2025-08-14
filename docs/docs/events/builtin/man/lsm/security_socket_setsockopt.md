---
title: TRACEE-SECURITY-SOCKET-SETSOCKOPT
section: 1
header: Tracee Event Manual
---

## NAME

**security_socket_setsockopt** - check permissions before setting socket options

## DESCRIPTION

This event is triggered by the Linux Security Module (LSM) hook when checking permissions before setting socket options via the setsockopt system call. It provides visibility into socket option modifications and their security implications.

Unlike the setsockopt syscall event which only provides the socket file descriptor, this LSM event provides detailed socket information including socket type and addressing details. However, it does not include the actual option value being set, as it occurs during the permission check phase.

## EVENT SETS

**lsm_hooks**, **net**, **net_sock**

## DATA FIELDS

**sockfd** (*int32*)
: File descriptor of the socket being modified

**level** (*int32*)
: Protocol level for the option (e.g., SOL_SOCKET, IPPROTO_TCP)

**optname** (*int32*)
: Option name being set

**local_addr** (*SockAddr*)
: Socket details including:
  - Socket type
  - Local IP address
  - Local port number
  - Protocol-specific information

## DEPENDENCIES

- `security_socket_setsockopt`: LSM hook for socket option setting

## USE CASES

- **Security monitoring**: Track socket configuration changes

- **Network control**: Audit socket option modifications

- **Compliance**: Verify socket security settings

- **Debugging**: Diagnose socket configuration issues

## SOCKET OPTIONS

Common socket option levels:

- **SOL_SOCKET**: Socket level options
  - SO_REUSEADDR: Address reuse
  - SO_KEEPALIVE: Connection keepalive
  - SO_BROADCAST: Broadcast permissions
  - SO_SNDBUF/SO_RCVBUF: Buffer sizes
  - SO_LINGER: Connection termination

- **IPPROTO_IP**: IP level options
  - IP_TTL: Time to live
  - IP_TOS: Type of service
  - IP_OPTIONS: IP header options

- **IPPROTO_TCP**: TCP level options
  - TCP_NODELAY: Disable Nagle's algorithm
  - TCP_MAXSEG: Maximum segment size
  - TCP_KEEPIDLE: Keepalive idle time

## SECURITY IMPLICATIONS

Important security aspects:

- **Resource limits**: Buffer size controls
- **Access control**: Broadcast permissions
- **Network behavior**: Protocol configurations
- **Connection handling**: Timeout settings
- **Performance tuning**: Protocol optimizations

## AUDIT TIPS

Key monitoring points:

- Changes to security-relevant options
- Unusual option combinations
- Privileged option modifications
- Protocol-specific security settings
- Resource allocation changes

## RELATED EVENTS

- **setsockopt**: System call for setting options
- **getsockopt**: System call for getting options
- **security_socket_bind**: Socket binding security
- **security_socket_connect**: Connection security
