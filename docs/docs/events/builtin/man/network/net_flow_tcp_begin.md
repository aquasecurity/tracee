---
title: TRACEE-NET-FLOW-TCP-BEGIN
section: 1
header: Tracee Event Manual
---

## NAME

**net_flow_tcp_begin** - TCP connection initiation detected

## DESCRIPTION

Triggered when a TCP connection is initiated, derived from raw network events captured by cgroup skb eBPF programs. This event monitors the TCP protocol's initiation phase by analyzing IP and TCP headers, specifically focusing on SYN, ACK, and FIN flag statuses to identify the start of TCP communication flows.

The event leverages kernel-level packet capture to provide critical data for network monitoring and security analysis, offering visibility into TCP connection establishment patterns.

This event is useful for:

- **Network monitoring**: Track TCP connection initiation patterns
- **Security analysis**: Detect unauthorized communication attempts
- **Performance monitoring**: Analyze network flow characteristics
- **Traffic analysis**: Monitor connection establishment patterns

## EVENT SETS

**network_events**, **flows**

## DATA FIELDS

**conn_direction** (*string*)
: Connection direction classified as 'incoming' or 'outgoing' based on packet direction and SYN flag status

**src** (*string*)
: Source IP address extracted from the IP header

**dst** (*string*)
: Destination IP address from the IP header

**src_port** (*uint16*)
: Source port from the TCP header

**dst_port** (*uint16*)
: Destination port from the TCP header

**src_dns** (*[]string*)
: Domain names related to the source IP, resolved through DNS cache

**dst_dns** (*[]string*)
: Domain names associated with the destination IP, resolved via DNS cache

## DEPENDENCIES

**Event Dependencies:**

- net_packet_flow_base: Base network packet flow event for network packet capture

## USE CASES

- **Network security monitoring**: Detect unusual connection patterns or unauthorized communications

- **Traffic analysis**: Monitor TCP connection establishment trends

- **Performance monitoring**: Analyze connection initiation latency and patterns

- **Incident response**: Track network communication during security incidents

- **Compliance monitoring**: Ensure network communications follow policy

## IMPLEMENTATION DETAILS

The event uses sophisticated packet capture mechanisms:

- **Flag Analysis**: Monitors SYN, ACK, and FIN flags for connection state detection
- **Low Overhead**: Optimized for minimal system impact during high-traffic scenarios
- **Header Parsing**: Efficiently extracts IP and TCP header information
- **DNS Integration**: Correlates IP addresses with domain names when available

## PERFORMANCE CONSIDERATIONS

Event efficiency depends on:

- Network traffic volume
- Complexity of monitored TCP flows
- System resources and configuration
- Proper data management and analysis

## RELATED EVENTS

- **net_tcp_connect**: Similar event based on security_socket_connect calls
- **net_flow_tcp_end**: TCP connection termination events
- **security_socket_connect**: Socket connection security events
- **net_packet_tcp**: Individual TCP packet capture events