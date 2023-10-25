
# Process standard input/output over socket detected

## Intro

The `StdioOverSocket` signature is a security mechanism aimed at detecting
potential Reverse Shell attacks based on process standard input/output
redirections to sockets.

## Description

Upon identifying that a process has its standard input/output redirected to a
socket, this signature raises an alert. Such behavior can be indicative of a
malicious actor attempting to establish a reverse shell, which provides them
interactive control over a compromised target.

## Purpose

The main goal of this signature is to identify and flag suspicious redirection
of standard I/O operations. Specifically, if these operations are redirected to
a socket, it can be a red flag, as this is a behavior commonly associated with a
Reverse Shell attack. By detecting such activities, proactive actions can be
taken to mitigate potential breaches.

## Metadata

- **ID**: TRC-101
- **Version**: 2
- **Name**: Process standard input/output over socket detected
- **EventName**: stdio_over_socket
- **Description**: This behavior hints at a Reverse Shell attack, where an interactive shell is activated from a target machine back to the attacker's machine.
- **Properties**:
  - **Severity**: 3
  - **Category**: execution
  - **Technique**: Unix Shell
  - **id**: attack-pattern--a9d4b653-6915-42af-98b2-5758c4ceee56
  - **external_id**: T1059.004

## Findings

Upon detection, the signature returns a `Finding` data structure with the following fields:

- **IP address**: (Type: string) The IP address associated with the socket.
- **Port**: (Type: string) The port associated with the socket.
- **File descriptor**: (Type: int) The file descriptor of the standard input/output (0, 1, 2 for stdin, stdout, stderr, respectively).

## Events Used

The signature responds to two primary events:

1. `security_socket_connect` - Indicates when a socket connection is made.
2. `socket_dup` - Denotes when a socket is duplicated.

Both events are sourced from `tracee`.
