---
title: TRACEE-NET-PACKET-ICMP
section: 1
header: Tracee Event Manual
---

## NAME

**net_packet_icmp** - capture and analyze ICMP network packets

## DESCRIPTION

Triggered for each ICMP (Internet Control Message Protocol) packet that reaches or leaves one of the processes being traced. This event provides detailed information about ICMP packets, including message types, codes, and protocol-specific fields used for network diagnostics and error reporting.

ICMP is a network layer protocol primarily used for diagnostic and control purposes, enabling devices to communicate error and status information about network conditions. It's commonly used by networking utilities like ping and traceroute for network connectivity testing and troubleshooting.

## EVENT SETS

**network_events**

## DATA FIELDS

**metadata** (*trace.PacketMetadata*)
: Network packet metadata containing:
  - Source IP address
  - Destination IP address
  - Network protocol
  - Packet length
  - Network interface

**proto_icmp** (*trace.ProtoICMP*)
: ICMP protocol information containing:
  - **typeCode** (*string*): ICMP message type and code (e.g., "EchoRequest", "EchoReply", "DestinationUnreachable")
  - **checksum** (*uint16*): ICMP checksum for error detection
  - **id** (*uint16*): Identifier field for matching requests/replies
  - **seq** (*uint16*): Sequence number for ordering messages

## DEPENDENCIES

**Event Dependencies:**

- net_packet_icmp_base: Base ICMP packet capture event for network packet parsing

## USE CASES

- **Network connectivity testing**: Monitor ping and connectivity testing tools

- **Network troubleshooting**: Analyze ICMP error messages and routing issues

- **Security monitoring**: Detect ICMP-based reconnaissance and attacks

- **Performance analysis**: Monitor network latency and packet loss

- **Infrastructure monitoring**: Track network health and reachability

## ICMP MESSAGE TYPES

Common ICMP message types captured:

### Diagnostic Messages
- **Echo Request (Type 8)**: Ping requests for connectivity testing
- **Echo Reply (Type 0)**: Ping responses confirming reachability

### Error Messages
- **Destination Unreachable (Type 3)**: Target host/network unreachable
- **Time Exceeded (Type 11)**: TTL expired, indicates routing loops
- **Parameter Problem (Type 12)**: IP header issues
- **Redirect (Type 5)**: Better route suggestions from routers

### Informational Messages
- **Timestamp Request/Reply**: Time synchronization
- **Information Request/Reply**: Network information queries

## ICMP CODES

Each ICMP type has specific codes providing additional context:

**Destination Unreachable (Type 3)**:
- Code 0: Network unreachable
- Code 1: Host unreachable
- Code 2: Protocol unreachable
- Code 3: Port unreachable

**Time Exceeded (Type 11)**:
- Code 0: TTL exceeded in transit
- Code 1: Fragment reassembly time exceeded

## SECURITY CONSIDERATIONS

Monitor for malicious ICMP usage:

- **ICMP flooding**: DoS attacks using ping floods
- **ICMP tunneling**: Data exfiltration through ICMP payloads
- **Network reconnaissance**: Port scanning using ICMP
- **Covert channels**: Hidden communication via ICMP

## NETWORK TROUBLESHOOTING

ICMP helps diagnose:

- **Connectivity issues**: Echo requests/replies for reachability testing
- **Routing problems**: Time exceeded messages indicating loops
- **MTU discovery**: Path MTU discovery using fragmentation needed messages
- **Network configuration**: Redirect messages for routing optimization

## RELATED EVENTS

- **net_packet_ipv4**: IPv4 packet capture (ICMP runs over IP)
- **net_packet_ipv6**: IPv6 packet capture (ICMPv6 for IPv6)
- **net_packet_icmpv6**: ICMPv6 packet capture for IPv6 networks
- **net_packet_udp**: UDP packet capture for comparison