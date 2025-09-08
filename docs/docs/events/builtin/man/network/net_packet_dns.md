---
title: TRACEE-NET-PACKET-DNS
section: 1
header: Tracee Event Manual
---

## NAME

**net_packet_dns** - capture and analyze DNS network packets

## DESCRIPTION

Triggered for each DNS packet that reaches or leaves one of the processes being traced. This event provides detailed information about DNS queries and responses, including all DNS header fields and resource records, enabling comprehensive DNS traffic analysis.

The Domain Name System (DNS) is fundamental to Internet operations, translating human-readable domain names into IP addresses. This event captures the complete DNS protocol exchange for monitoring, security analysis, and troubleshooting.

## EVENT SETS

**network_events**

## DATA FIELDS

**metadata** (*trace.PacketMetadata*)
: Network packet metadata containing:
  - Source IP address
  - Destination IP address
  - Source port number (typically 53 for DNS servers)
  - Destination port number (typically 53 for DNS)
  - Network protocol
  - Packet length
  - Network interface

**proto_dns** (*trace.ProtoDNS*)
: DNS protocol information containing:
  - **ID** (*uint16*): Transaction ID for matching queries to responses
  - **QR** (*uint8*): Query (0) or Response (1) flag
  - **opCode** (*string*): Operation code (e.g., "query", "iquery", "status")
  - **AA** (*uint8*): Authoritative Answer flag
  - **TC** (*uint8*): Truncation flag
  - **RD** (*uint8*): Recursion Desired flag
  - **RA** (*uint8*): Recursion Available flag
  - **Z** (*uint8*): Reserved field
  - **responseCode** (*string*): Response code (e.g., "no error", "name error")
  - **QDCount** (*uint16*): Number of questions
  - **ANCount** (*uint16*): Number of answer records
  - **NSCount** (*uint16*): Number of authority records
  - **ARCount** (*uint16*): Number of additional records
  - **questions** (*[]DNSQuestion*): DNS questions with name, type, and class
  - **answers** (*[]DNSResourceRecord*): DNS answer records
  - **authorities** (*[]DNSResourceRecord*): DNS authority records
  - **additionals** (*[]DNSResourceRecord*): DNS additional records

## DEPENDENCIES

**Event Dependencies:**

- net_packet_dns_base: Base DNS packet capture event for network packet parsing

## USE CASES

- **Security monitoring**: Detect DNS tunneling, DGA domains, and malicious DNS traffic

- **Network analysis**: Monitor DNS resolution patterns and performance

- **Troubleshooting**: Debug DNS resolution failures and timeouts

- **Compliance monitoring**: Track DNS queries for policy compliance

- **Threat hunting**: Identify suspicious domain resolution patterns

## DNS RECORD TYPES

Common DNS record types captured:

- **A**: IPv4 address records
- **AAAA**: IPv6 address records
- **CNAME**: Canonical name records
- **MX**: Mail exchange records
- **NS**: Name server records
- **PTR**: Pointer records for reverse lookups
- **SOA**: Start of authority records
- **TXT**: Text records
- **SRV**: Service records

## DNS FLAGS

Important DNS header flags:

- **QR**: Distinguishes queries from responses
- **AA**: Indicates authoritative responses
- **TC**: Signals truncated messages
- **RD**: Requests recursive resolution
- **RA**: Indicates recursive resolution support

## RELATED EVENTS

- **net_packet_udp**: UDP packet capture (DNS typically uses UDP)
- **net_packet_tcp**: TCP packet capture (DNS over TCP for large responses)
- **net_packet_dns_request**: DNS query-specific events
- **net_packet_dns_response**: DNS response-specific events