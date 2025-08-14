---
title: TRACEE-NET-PACKET-IPV4
section: 1
header: Tracee Event Manual
---

## NAME

**net_packet_ipv4** - capture IPv4 packet traffic

## DESCRIPTION

This event captures IPv4 (Internet Protocol version 4) packets in the network traffic. IPv4 is the foundational protocol of the Internet, responsible for addressing and routing packets between networks. The event provides detailed information about IPv4 packets, including header fields and network metadata.

IPv4 packets carry all types of Internet traffic, from web requests to email to streaming media. This event helps monitor network communication, diagnose routing issues, and analyze traffic patterns.

## EVENT SETS

**network_events**

## DATA FIELDS

**src** (*string*)
: Source IP address

**dst** (*string*)
: Destination IP address

**metadata** (*trace.PacketMetadata*)
: Additional packet metadata

**proto_ipv4** (*trace.ProtoIPv4*)
: IPv4 protocol information containing:
  - **version** (*uint8*): IP version (4)
  - **IHL** (*uint8*): Internet Header Length
  - **TOS** (*uint8*): Type of Service
  - **length** (*uint16*): Total packet length
  - **id** (*uint16*): Identification
  - **flags** (*uint8*): Fragment flags
  - **fragOffset** (*uint16*): Fragment offset
  - **TTL** (*uint8*): Time to Live
  - **protocol** (*string*): Upper layer protocol
  - **checksum** (*uint16*): Header checksum
  - **srcIP** (*string*): Source IP address
  - **dstIP** (*string*): Destination IP address

## DEPENDENCIES

- `net_packet_ip_base`: Base IP packet processing

## USE CASES

- **Network monitoring**: Track IP traffic

- **Routing analysis**: Debug routing issues

- **Traffic analysis**: Study packet patterns

- **Security monitoring**: Detect suspicious traffic

## HEADER FIELDS

Key IPv4 header components:

- **Version**: Always 4 for IPv4
- **IHL**: Header length in 32-bit words
- **TOS/DSCP**: Quality of service
- **Total Length**: Packet size in bytes
- **Identification**: Fragment identifier
- **Flags**: Fragmentation control
- **Fragment Offset**: Fragment position
- **TTL**: Hop limit counter
- **Protocol**: Upper layer protocol
- **Header Checksum**: Error detection
- **Source/Destination**: IP addresses

## FRAGMENTATION

Fragmentation controls:

- **Don't Fragment (DF)**: Prevent splitting
- **More Fragments (MF)**: More coming
- **Fragment Offset**: Position in data
- **Identification**: Group fragments
- **Total Length**: Fragment size
- **IHL**: Header size

## PROTOCOL NUMBERS

Common upper layer protocols:

- **1**: ICMP
- **2**: IGMP
- **6**: TCP
- **17**: UDP
- **47**: GRE
- **50**: ESP (IPsec)
- **51**: AH (IPsec)
- **89**: OSPF
- **132**: SCTP

## RELATED EVENTS

- **net_packet_ipv6**: IPv6 packet events
- **net_packet_tcp**: TCP packet events
- **net_packet_udp**: UDP packet events
- **net_packet_icmp**: ICMP packet events
