---
title: TRACEE-NET-PACKET-IPV6
section: 1
header: Tracee Event Manual
---

## NAME

**net_packet_ipv6** - capture IPv6 packet traffic

## DESCRIPTION

This event captures IPv6 (Internet Protocol version 6) packets in the network traffic. IPv6 is the next-generation Internet Protocol, designed to replace IPv4, offering vastly expanded addressing capabilities and improved features. The event provides detailed information about IPv6 packets, including header fields and network metadata.

IPv6 introduces a simplified header format, eliminates the need for NAT (Network Address Translation), and provides better support for mobility and security. This event helps monitor IPv6 network communication and analyze traffic patterns.

## EVENT SETS

**network_events**

## DATA FIELDS

**src** (*string*)
: Source IPv6 address

**dst** (*string*)
: Destination IPv6 address

**metadata** (*trace.PacketMetadata*)
: Additional packet metadata

**proto_ipv6** (*trace.ProtoIPv6*)
: IPv6 protocol information containing:
  - **version** (*uint8*): IP version (6)
  - **trafficClass** (*uint8*): Traffic class/DSCP
  - **flowLabel** (*uint32*): Flow label
  - **length** (*uint16*): Payload length
  - **nextHeader** (*string*): Next header type
  - **hopLimit** (*uint8*): Hop limit
  - **srcIP** (*string*): Source IPv6 address
  - **dstIP** (*string*): Destination IPv6 address

## DEPENDENCIES

- `net_packet_ip_base`: Base IP packet processing

## USE CASES

- **IPv6 monitoring**: Track IPv6 traffic

- **Flow analysis**: Study traffic patterns

- **Protocol migration**: Debug IPv4 to IPv6

- **Security monitoring**: Detect threats

## HEADER FIELDS

Key IPv6 header components:

- **Version**: Always 6 for IPv6
- **Traffic Class**: QoS marking
- **Flow Label**: Stream identification
- **Payload Length**: Data size
- **Next Header**: Protocol type
- **Hop Limit**: TTL equivalent
- **Source/Destination**: 128-bit addresses

## EXTENSION HEADERS

Common extension types:

- **Hop-by-Hop Options**: Per-hop processing
- **Routing**: Source routing
- **Fragment**: Packet fragmentation
- **Destination Options**: Destination processing
- **Authentication**: Security
- **Encapsulating Security**: Encryption
- **Mobility**: Mobile IPv6

## NEXT HEADER VALUES

Common protocol numbers:

- **0**: Hop-by-Hop Options
- **6**: TCP
- **17**: UDP
- **43**: Routing
- **44**: Fragment
- **50**: ESP
- **51**: AH
- **58**: ICMPv6
- **59**: No Next Header
- **60**: Destination Options

## RELATED EVENTS

- **net_packet_ipv4**: IPv4 packet events
- **net_packet_icmpv6**: ICMPv6 packet events
- **net_packet_tcp**: TCP packet events
- **net_packet_udp**: UDP packet events
