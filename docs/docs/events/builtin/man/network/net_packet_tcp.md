---
title: TRACEE-NET-PACKET-TCP
section: 1
header: Tracee Event Manual
---

## NAME

**net_packet_tcp** - capture and analyze TCP network packets

## DESCRIPTION

Triggered for each TCP packet that reaches or leaves one of the processes being traced. This event provides detailed information about TCP network communication, including all TCP header fields and connection metadata.

The Transmission Control Protocol (TCP) is a core protocol in the Internet protocol suite, responsible for reliable and connection-oriented data communication between devices over a network. This event captures the complete TCP header information for network analysis and monitoring.

## EVENT SETS

**network_events**

## DATA FIELDS

**metadata** (*trace.PacketMetadata*)
: Network packet metadata containing:
  - Source IP address
  - Destination IP address
  - Source port number
  - Destination port number
  - Network protocol
  - Packet length
  - Network interface

**proto_tcp** (*trace.ProtoTCP*)
: TCP protocol fields containing:
  - **srcPort** (*uint16*): Source port from TCP header
  - **dstPort** (*uint16*): Destination port from TCP header
  - **seq** (*uint32*): Sequence number
  - **ack** (*uint32*): Acknowledgment number
  - **dataOffset** (*uint8*): TCP header length in 32-bit words
  - **FIN** (*bool*): Finish flag - end of data transmission
  - **SYN** (*bool*): Synchronize flag - connection initiation
  - **RST** (*bool*): Reset flag - connection reset
  - **PSH** (*bool*): Push flag - immediate data delivery
  - **ACK** (*bool*): Acknowledgment flag - data receipt confirmation
  - **URG** (*bool*): Urgent flag - urgent data follows
  - **ECE** (*bool*): ECN-Echo flag - congestion notification
  - **CWR** (*bool*): Congestion Window Reduced flag
  - **NS** (*bool*): Nonce Sum flag - ECN protection
  - **window** (*uint16*): Window size for flow control
  - **checksum** (*uint16*): TCP checksum for error detection
  - **urgent** (*uint16*): Urgent pointer when URG flag is set

## DEPENDENCIES

**Event Dependencies:**

- net_packet_tcp_base: Base TCP packet capture event for network packet parsing

## USE CASES

- **Network security monitoring**: Detect malicious TCP connections

- **Performance analysis**: Monitor TCP flow control and congestion

- **Protocol debugging**: Analyze TCP handshakes and data transfer

- **Connection tracking**: Monitor TCP connection lifecycle

- **Bandwidth analysis**: Track data transfer patterns

## RELATED EVENTS

- **net_packet_ipv4**: IPv4 packet capture
- **net_packet_ipv6**: IPv6 packet capture
- **net_packet_udp**: UDP packet capture
- **net_flow_tcp_begin**: TCP connection establishment
- **net_flow_tcp_end**: TCP connection termination