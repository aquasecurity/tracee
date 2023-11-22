## IPv6

The IPv6 (Internet Protocol version 6) header is an essential component of the
IPv6 protocol suite and is responsible for routing packets across networks.
Unlike IPv4, IPv6 has a simplified header structure, which improves efficiency
and reduces the burden on routers.

Here's a description of the main IPv6 header fields:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  Traffic Class  |            Flow Label               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Payload Length         |  Next Header  |   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                   Source IPv6 Address (128 bits)              +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                 Destination IPv6 Address (128 bits)           +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

1. **Version (4 bits)**: Similar to IPv4, the Version field indicates the IP version being used, with IPv6 being denoted as '0110' in binary or '6' in decimal.
2. **Traffic Class (8 bits)**: The Traffic Class field is used for Quality of Service (QoS) and Differentiated Services Code Point (DSCP) markings, similar to IPv4's Type of Service (TOS) field. It helps in prioritizing packets based on their importance.
3. **Flow Label (20 bits)**: The Flow Label field is designed to help routers and switches identify and handle packets belonging to the same flow or session. It's primarily used for real-time and multimedia traffic to maintain consistency.
4. **Payload Length (16 bits)**: This field specifies the length of the payload (data) in the IPv6 packet, excluding the header. It's measured in bytes.
5. **Next Header (8 bits)**: The Next Header field is equivalent to IPv4's Protocol field. It specifies the type of the next header or extension header that follows the IPv6 header. Common values include ICMPv6 (58), TCP (6), and UDP (17).
6. **Hop Limit (8 bits)**: The Hop Limit field serves the same purpose as IPv4's Time to Live (TTL) field. It is a counter that limits the number of hops (routers) the packet can traverse before being discarded. When it reaches zero, the packet is dropped to prevent looping.
7. **Source IP Address (128 bits)** and **Destination IP Address (128 bits)**: These fields specify the source and destination IPv6 addresses, respectively. They uniquely identify the sender and recipient of the packet and are 128 bits in length, allowing for a vastly expanded address space compared to IPv4.

The simplified structure of the IPv6 header streamlines packet processing and
enhances the efficiency of routing in modern networks.

Additionally, IPv6 introduces extension headers for optional features and
options, which can be inserted between the main IPv6 header and the payload,
providing flexibility and extensibility in handling different packet types and
network services.

### net_packet_ipv6

The `net_packet_ipv6` event provides one event for each existing IPv6 packet
that reaches or leaves one of the processes being traced (or even "all OS
processes for the default run"). As arguments for this event you will find:
`src`, `dst`, `metadata` arguments (common to all networking events) and all `IPv6 header
fields`.

Example:

```console
tracee --output json --events net_packet_ipv6
```

```json
{"timestamp":1696271714895915799,"threadStartTime":1696271714890936591,"processorId":7,"processId":1105201,"cgroupId":5650,"threadId":1105201,"parentProcessId":1098248,"hostProcessId":1105201,"hostThreadId":1105201,"hostParentProcessId":1098248,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2001","eventName":"net_packet_ipv6","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"socket","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":520127464,"processEntityId":520127464,"parentEntityId":129643807,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::1"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::2"},{"name":"proto_ipv6","type":"trace.ProtoIPv6","value":{"version":6,"trafficClass":0,"flowLabel":917134,"length":40,"nextHeader":"TCP","hopLimit":64,"srcIP":"fd12:3456:789a::1","dstIP":"fd12:3456:789a::2"}}]}
{"timestamp":1696271714895946394,"threadStartTime":1696271709967284585,"processorId":7,"processId":1105169,"cgroupId":5650,"threadId":1105169,"parentProcessId":1037836,"hostProcessId":1105169,"hostThreadId":1105169,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2001","eventName":"net_packet_ipv6","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2333477623,"processEntityId":2333477623,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::1"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::2"},{"name":"proto_ipv6","type":"trace.ProtoIPv6","value":{"version":6,"trafficClass":0,"flowLabel":917134,"length":40,"nextHeader":"TCP","hopLimit":64,"srcIP":"fd12:3456:789a::1","dstIP":"fd12:3456:789a::2"}}]}
{"timestamp":1696271714895979201,"threadStartTime":1696271714890936591,"processorId":7,"processId":1105201,"cgroupId":5650,"threadId":1105201,"parentProcessId":1098248,"hostProcessId":1105201,"hostThreadId":1105201,"hostParentProcessId":1098248,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2001","eventName":"net_packet_ipv6","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":520127464,"processEntityId":520127464,"parentEntityId":129643807,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::1"},{"name":"proto_ipv6","type":"trace.ProtoIPv6","value":{"version":6,"trafficClass":0,"flowLabel":362266,"length":40,"nextHeader":"TCP","hopLimit":64,"srcIP":"fd12:3456:789a::2","dstIP":"fd12:3456:789a::1"}}]}
{"timestamp":1696271714895998772,"threadStartTime":1696271714890936591,"processorId":7,"processId":1105201,"cgroupId":5650,"threadId":1105201,"parentProcessId":1098248,"hostProcessId":1105201,"hostThreadId":1105201,"hostParentProcessId":1098248,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2001","eventName":"net_packet_ipv6","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"socket","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":520127464,"processEntityId":520127464,"parentEntityId":129643807,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::1"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::2"},{"name":"proto_ipv6","type":"trace.ProtoIPv6","value":{"version":6,"trafficClass":0,"flowLabel":917134,"length":32,"nextHeader":"TCP","hopLimit":64,"srcIP":"fd12:3456:789a::1","dstIP":"fd12:3456:789a::2"}}]}
{"timestamp":1696271714896006632,"threadStartTime":1696271709967284585,"processorId":7,"processId":1105169,"cgroupId":5650,"threadId":1105169,"parentProcessId":1037836,"hostProcessId":1105169,"hostThreadId":1105169,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2001","eventName":"net_packet_ipv6","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2333477623,"processEntityId":2333477623,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::1"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::2"},{"name":"proto_ipv6","type":"trace.ProtoIPv6","value":{"version":6,"trafficClass":0,"flowLabel":917134,"length":32,"nextHeader":"TCP","hopLimit":64,"srcIP":"fd12:3456:789a::1","dstIP":"fd12:3456:789a::2"}}]}
{"timestamp":1696271715216768685,"threadStartTime":1696271714890936591,"processorId":4,"processId":1105201,"cgroupId":5650,"threadId":1105201,"parentProcessId":1098248,"hostProcessId":1105201,"hostThreadId":1105201,"hostParentProcessId":1098248,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2001","eventName":"net_packet_ipv6","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"write","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":520127464,"processEntityId":520127464,"parentEntityId":129643807,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::1"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::2"},{"name":"proto_ipv6","type":"trace.ProtoIPv6","value":{"version":6,"trafficClass":0,"flowLabel":917134,"length":34,"nextHeader":"TCP","hopLimit":64,"srcIP":"fd12:3456:789a::1","dstIP":"fd12:3456:789a::2"}}]}
```

