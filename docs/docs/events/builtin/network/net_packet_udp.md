## UDP

The User Datagram Protocol (UDP) is one of the core transport layer protocols in
the Internet protocol suite (TCP/IP). Unlike TCP, UDP is a connectionless and
minimalistic protocol designed for simplicity and speed. It offers a best-effort
delivery service, making it suitable for applications where low overhead and
minimal delay are more critical than guaranteed data delivery. UDP packets,
often referred to as datagrams, consist of a relatively simple header and a data
payload.

Here's a description of the main UDP header fields:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Source Port (16 bits)     |  Destination Port (16 bits)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Length (16 bits)     |           Checksum (16 bits) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

1. **Source Port (16 bits)**: This field identifies the source port number, indicating the sender's endpoint for communication.
2. **Destination Port (16 bits)**: The Destination Port field specifies the port number of the receiving endpoint.
3. **Length (16 bits)**: The Length field indicates the length of the UDP header and the data payload. It measures the total size of the UDP packet in bytes.
4. **Checksum (16 bits)**: The Checksum field is used for error detection. It provides a simple checksum value that can be used to verify the integrity of the UDP header and data payload.

### net_packet_udp

The `net_packet_udp` event provides one event for each existing UDP packet that
reaches or leaves one of the processes being traced (or even "all OS processes
for the default run"). As arguments for this event you will find: `src`, `dst`,
`src_port`, `dst_port`, `metadata` arguments and all `UDP header fields`.

Example:

```console
tracee --output json --events net_packet_udp --events net_packet_udp.args.src=fd12:3456:789a::2
```

```json
{"timestamp":1696272374106561233,"threadStartTime":1696272081675489950,"processorId":1,"processId":1108786,"cgroupId":5650,"threadId":1108786,"parentProcessId":1037836,"hostProcessId":1108786,"hostThreadId":1108786,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2003","eventName":"net_packet_udp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"write","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":3953446441,"processEntityId":3953446441,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::1"},{"name":"src_port","type":"u16","value":8080},{"name":"dst_port","type":"u16","value":37294},{"name":"proto_udp","type":"trace.ProtoUDP","value":{"srcPort":8080,"dstPort":37294,"length":12,"checksum":21543}}]}
{"timestamp":1696272377447546123,"threadStartTime":1696272081675489950,"processorId":1,"processId":1108786,"cgroupId":5650,"threadId":1108786,"parentProcessId":1037836,"hostProcessId":1108786,"hostThreadId":1108786,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2003","eventName":"net_packet_udp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"write","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":3953446441,"processEntityId":3953446441,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::1"},{"name":"src_port","type":"u16","value":8080},{"name":"dst_port","type":"u16","value":37294},{"name":"proto_udp","type":"trace.ProtoUDP","value":{"srcPort":8080,"dstPort":37294,"length":12,"checksum":21543}}]}
{"timestamp":1696272377447582525,"threadStartTime":1696272102435727490,"processorId":1,"processId":1108865,"cgroupId":5650,"threadId":1108865,"parentProcessId":1098248,"hostProcessId":1108865,"hostThreadId":1108865,"hostParentProcessId":1098248,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2003","eventName":"net_packet_udp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2138584357,"processEntityId":2138584357,"parentEntityId":129643807,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::1"},{"name":"src_port","type":"u16","value":8080},{"name":"dst_port","type":"u16","value":37294},{"name":"proto_udp","type":"trace.ProtoUDP","value":{"srcPort":8080,"dstPort":37294,"length":12,"checksum":21543}}]}
{"timestamp":1696272386589678156,"threadStartTime":1696272081675489950,"processorId":6,"processId":1108786,"cgroupId":5650,"threadId":1108786,"parentProcessId":1037836,"hostProcessId":1108786,"hostThreadId":1108786,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2003","eventName":"net_packet_udp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"write","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":3953446441,"processEntityId":3953446441,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::1"},{"name":"src_port","type":"u16","value":8080},{"name":"dst_port","type":"u16","value":37294},{"name":"proto_udp","type":"trace.ProtoUDP","value":{"srcPort":8080,"dstPort":37294,"length":10,"checksum":21541}}]}
{"timestamp":1696272386589710441,"threadStartTime":1696272102435727490,"processorId":6,"processId":1108865,"cgroupId":5650,"threadId":1108865,"parentProcessId":1098248,"hostProcessId":1108865,"hostThreadId":1108865,"hostParentProcessId":1098248,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2003","eventName":"net_packet_udp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2138584357,"processEntityId":2138584357,"parentEntityId":129643807,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::1"},{"name":"src_port","type":"u16","value":8080},{"name":"dst_port","type":"u16","value":37294},{"name":"proto_udp","type":"trace.ProtoUDP","value":{"srcPort":8080,"dstPort":37294,"length":10,"checksum":21541}}]}
```
