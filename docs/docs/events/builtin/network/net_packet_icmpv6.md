## ICMPv6

The Internet Control Message Protocol version 6 (ICMPv6) is the counterpart of
ICMP for IPv6 networks. It serves a similar purpose as ICMP in IPv4 but is
adapted to the features and requirements of the IPv6 protocol. ICMPv6 is a
fundamental part of the IPv6 suite and plays a crucial role in network
diagnostics and control. Here's an overview of the ICMPv6 header and its
significance:

**ICMPv6 Header:**

The ICMPv6 header is composed of two main parts: the ICMPv6 message type and
code fields, followed by the ICMPv6 message body. Here are the primary
components of the ICMPv6 header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Type (8 bits)             |    Code (8 bits)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Checksum (16 bits)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Message Body (variable length)              +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

1. **Type (8 bits):** The Type field specifies the type of ICMPv6 message, such as Router Advertisement, Neighbor Solicitation, Neighbor Advertisement, and others. Each type serves a specific purpose in IPv6 network communication.
2. **Code (8 bits):** The Code field works in conjunction with the Type field to further categorize and define the specific ICMPv6 message type. It provides additional context or details related to the message.
3. **Checksum (16 bits):** The Checksum field is used to verify the integrity of the ICMPv6 message and its header during transmission, similar to ICMP in IPv4.
4. **Message Body (variable length):** The message body contains specific information or data associated with the ICMPv6 message type. The structure and content of the message body vary depending on the message type.

ICMPv6 serves various critical functions in IPv6 networks, including:

- **Neighbor Discovery:** ICMPv6 plays a crucial role in Neighbor Discovery, which is responsible for address resolution (finding a link-layer address given an IPv6 address), determining the reachability of neighboring devices, and duplicate address detection.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Type (8 bits)         |     Code (8 bits)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Checksum (16 bits)                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                  Target IPv6 Address (128 bits)               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                  Source Link-Layer Address (variable)         +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Router and Prefix Advertisement:** Routers use ICMPv6 to advertise their presence and provide configuration information to hosts on the network, including prefixes, default gateways, and other parameters.
- **Error Reporting:** Like ICMP in IPv4, ICMPv6 is used to report errors, such as Destination Unreachable and Time Exceeded, to indicate network issues or unreachable destinations.
- **Redirect:** ICMPv6 Redirect messages inform hosts about a more efficient next-hop router for a particular destination.
- **Multicast Listener Discovery:** ICMPv6 supports Multicast Listener Discovery, allowing nodes to report their interest in receiving multicast traffic and routers to keep track of active listeners.

ICMPv6 is an integral part of IPv6 network operations and diagnostics. It
facilitates efficient and reliable communication in IPv6 networks, enhances
network management, and simplifies various network-related tasks compared to its
IPv4 counterpart.

### net_packet_icmpv6

The `net_packet_icmpv6` event provides one event for each existing ICMPv6 packet
that reaches or leaves one of the processes being traced (or even "all OS
processes for the default run"). As arguments for this event you will find:
`src`, `dst`, `metadata` arguments (common to all networking events) and all `ICMPv6 header
fields`.

Example:

```console
tracee --output json --events net_packet_icmpv6
```

```json
{"timestamp":1696271035058952944,"threadStartTime":1696271035053334693,"processorId":3,"processId":1099372,"cgroupId":5650,"threadId":1099372,"parentProcessId":1037836,"hostProcessId":1099372,"hostThreadId":1099372,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"ping","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2005","eventName":"net_packet_icmpv6","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"sendto","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":1216694504,"processEntityId":1216694504,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::2"},{"name":"proto_icmpv6","type":"trace.ProtoICMPv6","value":{"typeCode":"EchoRequest","checksum":25155}}]}
{"timestamp":1696271035059002883,"threadStartTime":1696271035053334693,"processorId":3,"processId":1099372,"cgroupId":5650,"threadId":1099372,"parentProcessId":1037836,"hostProcessId":1099372,"hostThreadId":1099372,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"ping","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2005","eventName":"net_packet_icmpv6","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":1216694504,"processEntityId":1216694504,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::2"},{"name":"proto_icmpv6","type":"trace.ProtoICMPv6","value":{"typeCode":"EchoReply","checksum":24899}}]}
{"timestamp":1696271036064885442,"threadStartTime":1696271035053334693,"processorId":1,"processId":1099372,"cgroupId":5650,"threadId":1099372,"parentProcessId":1037836,"hostProcessId":1099372,"hostThreadId":1099372,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"ping","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2005","eventName":"net_packet_icmpv6","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"sendto","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":1216694504,"processEntityId":1216694504,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::2"},{"name":"proto_icmpv6","type":"trace.ProtoICMPv6","value":{"typeCode":"EchoRequest","checksum":32811}}]}
{"timestamp":1696271036064949538,"threadStartTime":1696271035053334693,"processorId":1,"processId":1099372,"cgroupId":5650,"threadId":1099372,"parentProcessId":1037836,"hostProcessId":1099372,"hostThreadId":1099372,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"ping","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2005","eventName":"net_packet_icmpv6","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":1216694504,"processEntityId":1216694504,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::2"},{"name":"proto_icmpv6","type":"trace.ProtoICMPv6","value":{"typeCode":"EchoReply","checksum":32555}}]}
{"timestamp":1696271037078256967,"threadStartTime":1696271035053334693,"processorId":3,"processId":1099372,"cgroupId":5650,"threadId":1099372,"parentProcessId":1037836,"hostProcessId":1099372,"hostThreadId":1099372,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"ping","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2005","eventName":"net_packet_icmpv6","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"sendto","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":1216694504,"processEntityId":1216694504,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::2"},{"name":"proto_icmpv6","type":"trace.ProtoICMPv6","value":{"typeCode":"EchoRequest","checksum":3574}}]}
{"timestamp":1696271037078303516,"threadStartTime":1696271035053334693,"processorId":3,"processId":1099372,"cgroupId":5650,"threadId":1099372,"parentProcessId":1037836,"hostProcessId":1099372,"hostThreadId":1099372,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"ping","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2005","eventName":"net_packet_icmpv6","matchedPolicies":[""],"argsNum":3,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":1216694504,"processEntityId":1216694504,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::2"},{"name":"proto_icmpv6","type":"trace.ProtoICMPv6","value":{"typeCode":"EchoReply","checksum":3318}}]}
```
