---
title: TRACEE-SECURITY-SOCKET-CREATE
section: 1
header: Tracee Event Manual
---

## NAME

**security_socket_create** - LSM socket creation monitoring

## DESCRIPTION

Triggered when the Linux Security Module (LSM) framework performs security checks on socket creation operations. This event provides information about the type of socket being created, including the protocol family, socket type, and protocol details, captured at the LSM level before socket establishment.

This event is valuable for network security monitoring as it captures socket creation with complete context, allowing security tools to monitor and control network communications before they occur.

## EVENT SETS

**lsm_hooks**, **net**, **net_sock**

## DATA FIELDS

**family** (*int32*)
: The protocol family (AF_INET, AF_INET6, AF_UNIX, etc.)

**type** (*int32*)
: The socket type (SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, etc.)

**protocol** (*int32*)
: The protocol number within the family

**kern** (*int32*)
: Flag indicating if this is a kernel socket

## DEPENDENCIES

**Kernel Probe:**

- security_socket_create (required): LSM hook for socket creation security checks

## USE CASES

- **Network monitoring**: Track network socket creation patterns

- **Security analysis**: Detect creation of unusual or privileged socket types

- **Protocol monitoring**: Monitor specific network protocols and families

- **Malware detection**: Identify suspicious network activity initiation

- **Network policy enforcement**: Monitor compliance with network access policies

## RELATED EVENTS

- **socket**: Socket creation system call
- **security_socket_listen**: Socket listen operations
- **security_socket_connect**: Socket connection operations
- **bind**: Socket address binding operations
