---
title: TRACEE-SOCKET-DUP
section: 1
header: Tracee Event Manual
---

## NAME

**socket_dup** - socket file descriptor duplication monitoring

## DESCRIPTION

Triggered when socket file descriptors are duplicated using the `dup`, `dup2`, or `dup3` system calls. This event specifically monitors the duplication of socket file descriptors, providing information about socket sharing, inheritance, and potential network communication patterns.

Socket duplication is commonly used for process communication, daemon operations, and network service management, but can also be used in exploitation techniques and covert communication channels.

## EVENT SETS

**none**

## DATA FIELDS

**oldfd** (*int32*)
: The original socket file descriptor being duplicated

**newfd** (*int32*)
: The new file descriptor created for the socket

**remote_addr** (*SockAddr*)
: The remote address associated with the socket

## DEPENDENCIES

**Kernel Probe:**

- dup (required): Duplicate file descriptor system call (entry + exit)
- dup2 (required): Duplicate file descriptor to specific descriptor system call (entry + exit)
- dup3 (required): Duplicate file descriptor with flags system call (entry + exit)

**Tail Calls:**
- sys_dup_exit_tail: Exit handling for dup system calls

## USE CASES

- **Socket sharing monitoring**: Track socket inheritance and sharing between processes

- **Network service analysis**: Monitor socket duplication in network daemons and services

- **Security monitoring**: Detect potential covert communication channels using socket duplication

- **Process communication tracking**: Understand inter-process communication patterns

- **Network debugging**: Debug socket sharing and inheritance issues

## RELATED EVENTS

- **socket**: Socket creation events
- **dup, dup2, dup3**: General file descriptor duplication events
- **Network socket events**: Related network communication monitoring
- **Process creation events**: Related process inheritance and communication
