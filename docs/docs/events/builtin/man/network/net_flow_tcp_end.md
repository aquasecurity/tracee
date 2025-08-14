# net_flow_tcp_end(1)

## NAME

net_flow_tcp_end - Event for monitoring the termination of TCP flows

## DESCRIPTION

The **net_flow_tcp_end** event is derived from base network raw events and is designed to monitor the termination of TCP flows. It leverages cgroup skb eBPF programs, focusing specifically on the TCP protocol's termination phase, and is instrumental in analyzing IP and TCP headers data to detect the end of TCP connections.

The event utilizes cgroup skb eBPF programs to intercept and analyze raw network events at the kernel level, with a particular emphasis on the TCP protocol's termination phase. It processes IP and TCP headers to pinpoint the conclusion of TCP communication flows. The event identifies the termination of TCP connections by analyzing the status of TCP flags, primarily focusing on the FIN and RST flags.

By examining these flags, the event provides valuable insights into the end of TCP connections, a critical component for comprehensive network monitoring and security analysis.

## EVENT SETS

**network_events**, **flows**

## DATA FIELDS

**conn_direction** (*string*)
: Indicates whether the terminated connection was 'incoming' or 'outgoing'

**src** (*string*)
: The source IP address, extracted from the IP header, from the side terminating the connection

**dst** (*string*)
: The destination IP address, obtained from the IP header, of the side receiving the termination

**src_port** (*uint16*)
: The source port number, derived from the TCP header

**dst_port** (*uint16*)
: The destination port number, ascertained from the TCP header

**src_dns** (*[]string*)
: Associated domain names for the source IP, resolved using DNS cache

**dst_dns** (*[]string*)
: Related domain names for the destination IP, determined through DNS cache

## DEPENDENCIES

**Event Dependencies:**

- net_packet_flow_base: Base network packet flow event for network packet capture

## USE CASES

- **Network Monitoring**: Monitor the termination of TCP connections for network security and performance analysis

- **Security Analysis**: Detect unusual traffic patterns, potential security threats, or abrupt end of communication

- **Connection Tracking**: Track the lifecycle of TCP connections from establishment to termination

## RELATED EVENTS

- **net_flow_tcp_begin**: Event for monitoring the beginning of TCP flows

- **net_packet_tcp**: TCP packet capture events

## PERFORMANCE CONSIDERATIONS

While designed to minimize system overhead, performance may vary based on the volume of network traffic and the complexity of monitored TCP flows. Efficient data management and analysis are key to leveraging the full potential of this event without affecting system performance adversely.