---
title: TRACEE-SOCKET-ACCEPT
section: 1
header: Tracee Event Manual
---

## NAME

**socket_accept** - socket connection acceptance monitoring

## DESCRIPTION

Triggered when a socket accepts an incoming connection through the `accept` or `accept4` system calls. This event provides comprehensive information about accepted connections, including local and remote addresses, enabling detailed monitoring of server-side network activity and connection patterns.

Socket acceptance is fundamental to server applications and network services, but monitoring these operations provides valuable insight into network communication patterns and potential security threats.

## EVENT SETS

**none**

## DATA FIELDS

**sockfd** (*int32*)
: The socket file descriptor accepting the connection

**local_addr** (*SockAddr*)
: The local address of the accepting socket

**remote_addr** (*SockAddr*)
: The remote address of the connecting client

## DEPENDENCIES

**Kernel Probe:**

- sys_enter (required): System call entry tracking for accept/accept4 calls
- sys_exit (required): System call exit tracking for accept/accept4 calls

**Event Dependencies:**

- security_socket_accept (required): LSM security checks for socket acceptance

**Tail Calls:**
- syscall__accept4: System call handling for accept/accept4
- sys_exit_init: System call exit initialization

## USE CASES

- **Server monitoring**: Monitor incoming connections to network services and applications

- **Security analysis**: Detect unusual connection patterns or potential network attacks

- **Network debugging**: Debug connection acceptance issues and server behavior

- **Connection tracking**: Track network connections for monitoring and analysis

- **Performance analysis**: Analyze connection acceptance performance and patterns

## RELATED EVENTS

- **security_socket_accept**: LSM security checks for socket acceptance
- **socket**: Socket creation events
- **bind**: Socket address binding events
- **listen**: Socket listening events
