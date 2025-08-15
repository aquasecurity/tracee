---
title: TRACEE-NET-PACKET-UDP
section: 1
header: Tracee Event Manual
---

## NAME

**net_packet_udp** - capture and analyze UDP network packets

## DESCRIPTION

Triggered for each UDP (User Datagram Protocol) packet that reaches or leaves one of the processes being traced. This event provides detailed information about UDP datagrams, including header fields and addressing information for connectionless network communication.

UDP is a connectionless, minimalistic transport layer protocol designed for simplicity and speed. It offers best-effort delivery service, making it suitable for applications where low overhead and minimal delay are more critical than guaranteed data delivery. UDP is commonly used for DNS, DHCP, streaming media, online gaming, and other real-time applications.

This event is useful for:

- **Network monitoring**: Track UDP-based application traffic and communication patterns
- **DNS analysis**: Monitor DNS queries and responses
- **Real-time applications**: Analyze streaming, gaming, and VoIP traffic
- **Network troubleshooting**: Debug UDP connectivity and performance issues

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

**proto_udp** (*trace.ProtoUDP*)
: UDP protocol information containing:
  - **srcPort** (*uint16*): Source port number
  - **dstPort** (*uint16*): Destination port number
  - **length** (*uint16*): Length of UDP header and data payload
  - **checksum** (*uint16*): Checksum for error detection

## DEPENDENCIES

**Event Dependencies:**

- net_packet_udp_base: Base UDP packet capture event for network packet parsing

## USE CASES

- **DNS monitoring**: Track DNS queries and responses for security and performance analysis

- **DHCP analysis**: Monitor network configuration and IP address assignment

- **Streaming media**: Analyze video/audio streaming performance and quality

- **Gaming traffic**: Monitor online gaming communication and latency

- **IoT communication**: Track Internet of Things device communication patterns

- **Network security**: Detect UDP-based attacks and reconnaissance

## UDP CHARACTERISTICS

**Connectionless Protocol:**
- No connection establishment or teardown required
- Each datagram is independent and self-contained
- No delivery guarantees or error recovery

**Minimal Overhead:**
- Simple 8-byte header (vs TCP's minimum 20 bytes)
- No flow control or congestion control
- Suitable for real-time applications with latency constraints

**Best-Effort Delivery:**
- No acknowledgment of received packets
- No automatic retransmission of lost packets
- Application responsible for reliability if needed

## COMMON UDP APPLICATIONS

**Well-Known Port Services:**
- **DNS (Port 53)**: Domain Name System queries and responses
- **DHCP (Ports 67/68)**: Dynamic Host Configuration Protocol
- **SNMP (Port 161)**: Simple Network Management Protocol
- **NTP (Port 123)**: Network Time Protocol
- **TFTP (Port 69)**: Trivial File Transfer Protocol

**Real-Time Applications:**
- **VoIP**: Voice over IP communication
- **Video streaming**: Live video broadcasts and conferencing
- **Online gaming**: Real-time multiplayer game data
- **IoT sensors**: Sensor data collection and telemetry

## UDP HEADER ANALYSIS

The UDP header contains critical information:

**Source Port (16 bits):**
- Identifies the sending application or service
- Used for return communication path

**Destination Port (16 bits):**
- Specifies the target application or service
- Determines how the packet should be processed

**Length (16 bits):**
- Total size of UDP header (8 bytes) plus data payload
- Minimum value is 8 (header only)

**Checksum (16 bits):**
- Optional error detection mechanism
- Can be zero to disable checksum verification

## SECURITY CONSIDERATIONS

Monitor for malicious UDP usage:

- **UDP flooding**: Denial of service attacks using UDP traffic
- **DNS amplification**: Using DNS servers to amplify attack traffic
- **UDP scanning**: Port scanning using UDP packets
- **Data exfiltration**: Covert channels using UDP communication
- **Reflection attacks**: Using UDP services to reflect traffic

## PERFORMANCE CHARACTERISTICS

UDP offers several performance advantages:

- **Low latency**: No connection setup overhead
- **High throughput**: Minimal protocol processing
- **Scalability**: Stateless nature reduces server resource usage
- **Efficiency**: Smaller header size and less CPU overhead

## TROUBLESHOOTING WITH UDP EVENTS

Common issues to investigate:

- **Packet loss**: Missing datagrams in communication flows
- **Port unreachable**: ICMP responses for closed UDP ports
- **Checksum errors**: Data corruption during transmission
- **Firewall blocking**: Dropped packets due to security policies

## RELATED EVENTS

- **net_packet_tcp**: TCP packet capture for comparison
- **net_packet_dns**: Specific DNS protocol analysis
- **net_packet_ipv4**: IPv4 packet capture (UDP runs over IP)
- **net_packet_ipv6**: IPv6 packet capture for IPv6 UDP traffic