---
title: TRACEE-SECURITY-SOCKET-LISTEN
section: 1
header: Tracee Event Manual
---

## NAME

**security_socket_listen** - LSM socket listen operation monitoring

## DESCRIPTION

Triggered when the Linux Security Module (LSM) framework performs security checks on socket listen operations. This event provides information about sockets being set up to accept incoming connections, including the socket file descriptor, local address, and connection backlog.

This event is crucial for monitoring server-side network activity and detecting when processes start listening for incoming connections, which can indicate service startup or potential security threats.

## EVENT SETS

**lsm_hooks**, **net**, **net_sock**

## DATA FIELDS

**sockfd** (*int32*)
: The socket file descriptor being set to listen

**local_addr** (*SockAddr*)
: The local address the socket is bound to

**backlog** (*int32*)
: The maximum number of pending connections

## DEPENDENCIES

**Kernel Probe:**

- security_socket_listen (required): LSM hook for socket listen security checks

**Kernel Tracepoint:**

- raw_syscalls:sys_enter (required): System call entry tracking for context

**Tail Calls:**
- sys_enter_init_tail: Context initialization for listen system call

## USE CASES

- **Service monitoring**: Track when network services start accepting connections

- **Security auditing**: Detect unauthorized listening services and potential backdoors

- **Network service management**: Monitor service startup and configuration

- **Threat hunting**: Identify suspicious listening processes and covert communication channels

- **Compliance monitoring**: Ensure network services comply with security policies

## RELATED EVENTS

- **listen**: Socket listen system call
- **security_socket_create**: Socket creation operations
- **bind**: Socket address binding operations
- **accept**: Socket connection acceptance events