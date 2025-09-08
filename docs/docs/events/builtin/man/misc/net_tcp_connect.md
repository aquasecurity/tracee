---
title: TRACEE-NET-TCP-CONNECT
section: 1
header: Tracee Event Manual
---

## NAME

**net_tcp_connect** - monitor TCP connection attempts with DNS resolution

## DESCRIPTION

A high-level event derived from the security_socket_connect LSM (Linux Security Module) hook that monitors TCP connection attempts. This event provides enriched information about outbound connections, including DNS resolution data for destination addresses.

Unlike direct kernel probes, this LSM-based approach avoids Time-Of-Check to Time-Of-Use (TOCTOU) race conditions, making it a reliable source for connection monitoring. The event combines low-level connection details with high-level DNS context for comprehensive network visibility.

## EVENT SETS

**none**

## DATA FIELDS

**dst_ip** (*string*)
: The destination IP address of the connection attempt

**dst_port** (*uint16*)
: The destination port number

**results** (*[]string*)
: DNS resolutions associated with the destination IP

## DEPENDENCIES

**LSM Hook:**

- security_socket_connect (required): LSM hook for socket connection security checks

## USE CASES

- **Security monitoring**: Detect connections to suspicious or malicious endpoints

- **Network behavior analysis**: Track application connection patterns

- **DNS correlation**: Link IP addresses with domain names

- **Intrusion detection**: Identify unusual connection patterns

- **Compliance monitoring**: Track network connections for audit requirements

## PERFORMANCE CONSIDERATIONS

The event generates data for each connection attempt, which can be substantial in high-traffic environments. Consider:

- **Data volume**: High network activity generates many events
- **DNS resolution**: Additional overhead for DNS lookups
- **Storage requirements**: Connection logs can grow quickly
- **Analysis overhead**: Processing connection patterns requires resources

## SECURITY IMPLICATIONS

The event provides valuable security insights:

- **Connection tracking**: Monitor all outbound connection attempts
- **DNS context**: Link IPs to domain names for threat analysis
- **Pattern detection**: Identify unusual connection behavior
- **Endpoint verification**: Validate connection destinations

## RELATED EVENTS

- **net_flow_tcp_begin**: Network flow-based connection tracking
- **security_socket_connect**: Low-level socket connection events
- **net_packet_tcp**: TCP packet capture events
- **net_packet_dns**: DNS packet analysis events
