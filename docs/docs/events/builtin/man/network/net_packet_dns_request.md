# net_packet_dns_request(1)

## NAME

net_packet_dns_request - DNS request packet capture event

## DESCRIPTION

The **net_packet_dns_request** event shows DNS queries only. It provides one event for each existing DNS packet containing a query that reaches or leaves one of the processes being traced (or all OS processes for the default run).

DNS queries come in various types, each serving a specific purpose in the domain name resolution process or in retrieving information from DNS servers. Common types include:

- **Standard Query (A or AAAA)**: Requests IPv4 (A) or IPv6 (AAAA) address for a domain name
- **Inverse Query (PTR)**: Provides an IP address and asks for the associated domain name
- **Mail Exchange Query (MX)**: Retrieves mail exchange servers for a specific domain
- **Name Server Query (NS)**: Discovers authoritative name servers for a domain
- **Start of Authority Query (SOA)**: Retrieves SOA record containing essential domain information
- **Service Query (SRV)**: Locates services associated with a specific domain
- **Text Query (TXT)**: Retrieves text-based information associated with a domain
- **Canonical Name Query (CNAME)**: Finds the canonical name of an alias domain

## EVENT SETS

This event is included in the following event sets:

- **network_events**: Network-related events

## DATA FIELDS

**metadata** (*trace.PacketMetadata*)
: Network packet metadata containing:
  - Source IP address
  - Destination IP address
  - Source port number
  - Destination port number
  - Network protocol (typically UDP/17 for DNS)
  - Packet length
  - Network interface

**dns_questions** (*[]trace.DnsQueryData*)
: Array of DNS query data containing:
  - Domain name being queried
  - Type of DNS query (A, AAAA, MX, etc.)
  - Query class (typically "IN" for Internet)

## DEPENDENCIES

**Event Dependencies:**

- net_packet_dns_base: Base DNS packet capture event for network packet parsing

## USE CASES

- **DNS Monitoring**: Track all DNS queries made by processes for security analysis

- **Network Forensics**: Analyze DNS query patterns to identify malicious domains

- **Performance Analysis**: Monitor DNS query frequency and response patterns

- **Security Detection**: Detect DNS tunneling, exfiltration, or C&C communication

## RELATED EVENTS

- **net_packet_dns**: General DNS packet events (both requests and responses)

- **net_packet_dns_response**: DNS response packet events

## EXAMPLE

```console
$ tracee --output json --events net_packet_dns_request
```

The event captures DNS queries with detailed metadata about the network packet and the specific DNS question being asked.
