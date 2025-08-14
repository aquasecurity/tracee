---
title: TRACEE-NET-PACKET-ICMPV6
section: 1
header: Tracee Event Manual
---

## NAME

**net_packet_icmpv6** - capture ICMPv6 packet traffic

## DESCRIPTION

This event captures ICMPv6 (Internet Control Message Protocol version 6) packets in the network traffic. ICMPv6 is a core protocol in IPv6 networks, used for error reporting, network diagnostics, and neighbor discovery. The event provides detailed information about ICMPv6 messages, including their types, codes, and network metadata.

ICMPv6 is essential for IPv6 network operations, handling tasks like router discovery, address autoconfiguration, and path MTU discovery. This event helps monitor these critical network functions and diagnose connectivity issues.

## EVENT SETS

**default**, **network_events**

## DATA FIELDS

**src** (*string*)
: Source IPv6 address

**dst** (*string*)
: Destination IPv6 address

**metadata** (*trace.PacketMetadata*)
: Additional packet metadata

**proto_icmpv6** (*trace.ProtoICMPv6*)
: ICMPv6 protocol information containing:
  - **typeCode** (*string*): ICMPv6 message type and code
  - **checksum** (*uint16*): Message checksum

## DEPENDENCIES

- `net_packet_icmpv6_base`: Base ICMPv6 packet processing

## USE CASES

- **Network diagnostics**: Debug connectivity issues

- **Neighbor discovery**: Monitor IPv6 address resolution

- **Router discovery**: Track router advertisements

- **Path MTU**: Monitor path MTU discovery

## MESSAGE TYPES

Common ICMPv6 messages:

- **Error Messages**:
  - Destination Unreachable
  - Packet Too Big
  - Time Exceeded
  - Parameter Problem

- **Informational Messages**:
  - Echo Request/Reply
  - Router Advertisement
  - Router Solicitation
  - Neighbor Advertisement
  - Neighbor Solicitation
  - Redirect

## PROTOCOL FUNCTIONS

Key ICMPv6 roles:

- **Neighbor Discovery Protocol (NDP)**:
  - Address resolution
  - Router discovery
  - Prefix discovery
  - Parameter discovery
  - Address autoconfiguration
  - Duplicate address detection
  - Neighbor unreachability detection

- **Path MTU Discovery**:
  - Packet size optimization
  - Fragmentation avoidance
  - Path MTU updates

## SECURITY IMPLICATIONS

Important security aspects:

- **Reconnaissance**: Network mapping
- **DoS attacks**: ICMPv6 flooding
- **Man-in-the-middle**: NDP spoofing
- **Router hijacking**: Fake advertisements
- **Address conflicts**: DAD attacks
- **Route manipulation**: Redirect attacks

## RELATED EVENTS

- **net_packet_ipv6**: IPv6 packet events
- **net_packet_icmp**: ICMPv4 packet events
- **net_packet_tcp**: TCP packet events
- **net_packet_udp**: UDP packet events
