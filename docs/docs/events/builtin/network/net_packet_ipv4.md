## IPv4

The IPv4 (Internet Protocol version 4) header is a fundamental part of the IP
protocol suite and is used for routing packets of data across networks. It
contains various fields that provide crucial information about the packet and
help in its delivery.

Here's a description of the IPv4 header fields:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |   TOS   |         Total Length                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Identification          |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  TTL  |   Protocol  |        Header Checksum                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Source IP Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Destination IP Address                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

1. **Version (4 bits)**: This field indicates the IP version being used, with IPv4 being denoted as '0100' in binary or '4' in decimal.
2. **Internet Header Length (IHL, 4 bits)**: The IHL field specifies the length of the entire IPv4 header in 32-bit words. It is needed because the header can have variable length options, so this field tells where the actual data begins.
3. **Type of Service (TOS, 8 bits)**: This field is used for Quality of Service (QoS) and Differentiated Services Code Point (DSCP) markings. It helps routers prioritize packets based on their importance, such as VoIP traffic getting higher priority than email.
4. **Total Length (16 bits)**: The Total Length field specifies the total size of the IPv4 packet, including both the header and the payload (data). It is measured in bytes and ranges from 20 to 65,535 bytes.
5. **Identification (16 bits)**: This field is primarily used for fragmentation and reassembly of packets. It assigns a unique identifier to each packet, allowing fragmented packets to be reassembled correctly.
6. **Flags (3 bits) and Fragment Offset (13 bits)**: These fields work together for packet fragmentation. The Flags field includes control bits like 'Don't Fragment' (DF) and 'More Fragments' (MF). The Fragment Offset indicates the position of the fragment in the original packet's data.
7. **Time to Live (TTL, 8 bits)**: TTL is a counter that starts with a certain value when the packet is created and is decremented by one each time it passes through a router. If it reaches zero, the packet is discarded to prevent it from circulating indefinitely.
8. **Protocol (8 bits)**: This field specifies the upper-layer protocol to which the packet should be delivered after the IP layer processes it. For example, a value of 6 indicates TCP, while 17 indicates UDP.
9. **Header Checksum (16 bits)**: The checksum field is used for error-checking the header. It ensures the integrity of the header during transmission.
10. **Source IP Address (32 bits)** and **Destination IP Address** (32 bits): These fields specify the source and destination IP addresses, respectively, identifying the sender and recipient of the packet.

The IPv4 header is crucial for the proper routing and delivery of packets across
the Internet, and these fields play a vital role in ensuring data reaches its
intended destination accurately and efficiently.

### net_packet_ipv4

The `net_packet_ipv4` event provides one event for each existing IPv4 packet
that reaches or leaves one of the processes being traced (or even "all OS
processes for the default run"). As arguments for this event you will find:
`src`, `dst`, `metadata` arguments (common to all networking events) and all `IPv4 header
fields`.

Example:

``` console
tracee --output json --events net_packet_ipv4 --events net_packet_ipv4.args.src=10.10.11.2
```

```json
{"timestamp":1696271464003181761,"threadStartTime":1696271463999022297,"processorId":2,"processId":1103574,"cgroupId":5650,"threadId":1103574,"parentProcessId":1098248,"hostProcessId":1103574,"hostThreadId":1103574,"hostParentProcessId":1098248,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2000","eventName":"net_packet_ipv4","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"socket","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2347021303,"processEntityId":2347021303,"parentEntityId":129643807,"args":[{"name":"src","type":"const char*","value":"10.10.11.2"},{"name":"dst","type":"const char*","value":"10.10.11.2"},{"name":"proto_ipv4","type":"trace.ProtoIPv4","value":{"version":4,"IHL":5,"TOS":0,"length":60,"id":21515,"flags":2,"fragOffset":0,"TTL":64,"protocol":"TCP","checksum":48281,"srcIP":"10.10.11.2","dstIP":"10.10.11.2"}}]}
{"timestamp":1696271464003224112,"threadStartTime":1696271455012758640,"processorId":2,"processId":1103525,"cgroupId":5650,"threadId":1103525,"parentProcessId":1037836,"hostProcessId":1103525,"hostThreadId":1103525,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2000","eventName":"net_packet_ipv4","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2580724346,"processEntityId":2580724346,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"10.10.11.2"},{"name":"dst","type":"const char*","value":"10.10.11.2"},{"name":"proto_ipv4","type":"trace.ProtoIPv4","value":{"version":4,"IHL":5,"TOS":0,"length":60,"id":21515,"flags":2,"fragOffset":0,"TTL":64,"protocol":"TCP","checksum":48281,"srcIP":"10.10.11.2","dstIP":"10.10.11.2"}}]}
{"timestamp":1696271464003252321,"threadStartTime":1696271455012758640,"processorId":2,"processId":1103525,"cgroupId":5650,"threadId":1103525,"parentProcessId":1037836,"hostProcessId":1103525,"hostThreadId":1103525,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2000","eventName":"net_packet_ipv4","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"socket","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2580724346,"processEntityId":2580724346,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"10.10.11.2"},{"name":"dst","type":"const char*","value":"10.10.11.2"},{"name":"proto_ipv4","type":"trace.ProtoIPv4","value":{"version":4,"IHL":5,"TOS":0,"length":60,"id":0,"flags":2,"fragOffset":0,"TTL":64,"protocol":"TCP","checksum":4261,"srcIP":"10.10.11.2","dstIP":"10.10.11.2"}}]}
{"timestamp":1696271464003264004,"threadStartTime":1696271463999022297,"processorId":2,"processId":1103574,"cgroupId":5650,"threadId":1103574,"parentProcessId":1098248,"hostProcessId":1103574,"hostThreadId":1103574,"hostParentProcessId":1098248,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2000","eventName":"net_packet_ipv4","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2347021303,"processEntityId":2347021303,"parentEntityId":129643807,"args":[{"name":"src","type":"const char*","value":"10.10.11.2"},{"name":"dst","type":"const char*","value":"10.10.11.2"},{"name":"proto_ipv4","type":"trace.ProtoIPv4","value":{"version":4,"IHL":5,"TOS":0,"length":60,"id":0,"flags":2,"fragOffset":0,"TTL":64,"protocol":"TCP","checksum":4261,"srcIP":"10.10.11.2","dstIP":"10.10.11.2"}}]}
{"timestamp":1696271464003290303,"threadStartTime":1696271463999022297,"processorId":2,"processId":1103574,"cgroupId":5650,"threadId":1103574,"parentProcessId":1098248,"hostProcessId":1103574,"hostThreadId":1103574,"hostParentProcessId":1098248,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2000","eventName":"net_packet_ipv4","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"socket","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2347021303,"processEntityId":2347021303,"parentEntityId":129643807,"args":[{"name":"src","type":"const char*","value":"10.10.11.2"},{"name":"dst","type":"const char*","value":"10.10.11.2"},{"name":"proto_ipv4","type":"trace.ProtoIPv4","value":{"version":4,"IHL":5,"TOS":0,"length":52,"id":21516,"flags":2,"fragOffset":0,"TTL":64,"protocol":"TCP","checksum":48288,"srcIP":"10.10.11.2","dstIP":"10.10.11.2"}}]}
{"timestamp":1696271464003301870,"threadStartTime":1696271455012758640,"processorId":2,"processId":1103525,"cgroupId":5650,"threadId":1103525,"parentProcessId":1037836,"hostProcessId":1103525,"hostThreadId":1103525,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2000","eventName":"net_packet_ipv4","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2580724346,"processEntityId":2580724346,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"10.10.11.2"},{"name":"dst","type":"const char*","value":"10.10.11.2"},{"name":"proto_ipv4","type":"trace.ProtoIPv4","value":{"version":4,"IHL":5,"TOS":0,"length":52,"id":21516,"flags":2,"fragOffset":0,"TTL":64,"protocol":"TCP","checksum":48288,"srcIP":"10.10.11.2","dstIP":"10.10.11.2"}}]}
```
