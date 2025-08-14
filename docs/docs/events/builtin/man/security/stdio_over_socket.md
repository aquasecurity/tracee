---
title: TRACEE-STDIO-OVER-SOCKET
section: 1
header: Tracee Event Manual
---

## NAME

**stdio_over_socket** - process standard input/output over socket detection

## DESCRIPTION

Triggered when a process has its standard input/output redirected to a socket, which is commonly associated with reverse shell attacks. This signature detects when an attacker establishes an interactive shell from a compromised target back to their machine by redirecting stdin, stdout, and stderr through network sockets.

Standard I/O redirection to sockets is a fundamental technique used in reverse shells, where the attacker gains interactive control over a compromised system. This behavior is highly suspicious in normal operations and typically indicates malicious activity.

This signature is useful for:

- **Reverse shell detection**: Identify active reverse shell connections
- **Command and control monitoring**: Detect interactive malicious sessions
- **Post-exploitation activity**: Identify attacker interaction with compromised systems

## SIGNATURE METADATA

- **ID**: TRC-101
- **Version**: 2
- **Severity**: 3 (High threat level)
- **Category**: execution
- **Technique**: Unix Shell
- **MITRE ATT&CK**: T1059.004

## EVENT SETS

**signatures**, **execution**

## DATA FIELDS

**ip_address** (*string*)
: The IP address associated with the socket connection

**port** (*string*)
: The port number associated with the socket connection

**file_descriptor** (*integer*)
: The file descriptor of the standard input/output (0=stdin, 1=stdout, 2=stderr)

## DEPENDENCIES

**System Events:**

- security_socket_connect (required): Monitors socket connection establishment
- socket_dup (required): Monitors socket duplication for I/O redirection

## DETECTION LOGIC

The signature monitors for:

1. **Socket connections** being established to external addresses
2. **File descriptor duplication** of sockets to standard I/O descriptors (0, 1, 2)
3. **Process correlation** to identify which processes are redirecting I/O

## USE CASES

- **Intrusion detection**: Identify active reverse shell connections

- **Incident response**: Detect ongoing attacker interaction with compromised systems

- **Network security**: Monitor for unauthorized outbound interactive sessions

- **Malware analysis**: Identify payload behavior in sandbox environments

- **Forensic investigation**: Track attacker command and control activities

## REVERSE SHELL TECHNIQUES

Common reverse shell establishment methods:

- **Netcat reverse shells**: Using nc to redirect shell I/O over network
- **Bash reverse shells**: Direct bash socket redirection techniques
- **Python/Perl/PHP shells**: Scripting language-based reverse shells
- **Binary exploitation**: Buffer overflow leading to shell redirection
- **Web shell uploads**: Uploaded scripts creating reverse connections

## SOCKET REDIRECTION METHODS

Attackers typically use these techniques:

- **dup2() system calls**: Duplicating socket file descriptors to stdin/stdout/stderr
- **Process spawning**: Creating child processes with redirected I/O
- **Shell command execution**: Running commands with I/O redirection operators
- **Programming language sockets**: Using socket libraries to create interactive sessions

## NETWORK INDICATORS

Look for associated network patterns:

- **Outbound connections** to unexpected IP addresses
- **Non-standard ports** for interactive sessions
- **Persistent connections** with bidirectional traffic
- **Command-like traffic patterns** in network streams

## EVASION TECHNIQUES

Attackers may attempt evasion through:

- **Encryption**: Using SSL/TLS to encrypt reverse shell traffic
- **Protocol tunneling**: Hiding shells within legitimate protocols (HTTP, DNS)
- **Traffic obfuscation**: Disguising shell traffic as normal application data
- **Timing manipulation**: Using delays to avoid detection thresholds

## LEGITIMATE SCENARIOS

Some legitimate uses that may trigger detection:

- **Remote administration tools**: SSH, RDP, VNC sessions
- **Development tools**: Remote debugging or development environments
- **Automation scripts**: Legitimate automation connecting to remote systems
- **Monitoring tools**: System monitoring with network reporting

## PREVENTION STRATEGIES

- **Network segmentation**: Limit outbound connectivity from sensitive systems
- **Egress filtering**: Block unnecessary outbound ports and protocols
- **Application whitelisting**: Prevent unauthorized binary execution
- **Process monitoring**: Monitor process creation and I/O redirection
- **Network monitoring**: Detect unusual outbound connection patterns

## RELATED EVENTS

- **security_socket_connect**: Primary detection for socket connections
- **socket_dup**: Primary detection for file descriptor duplication
- **sched_process_exec**: Process execution context
- **net_packet_tcp**: Network traffic analysis