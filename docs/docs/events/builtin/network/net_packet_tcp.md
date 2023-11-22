## TCP

The Transmission Control Protocol (TCP) is a core protocol in the Internet
protocol suite, responsible for reliable and connection-oriented data
communication between devices over a network. The TCP header contains various
fields that govern the behavior of the protocol and ensure the reliable delivery
of data.

Here's a description of the TCP header fields:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Source Port (16 bits)     |  Destination Port (16 bits)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              Sequence Number (32 bits)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Acknowledgment Number (32 bits)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Data Offset |  Reserved   |  Control Flags (6 bits)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Window Size (16 bits)    |  Checksum (16 bits)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Urgent Pointer (16 bits)   |                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|              Options (variable length, if any)                |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

1. **Source Port (16 bits) and Destination Port (16 bits):** These fields specify the source and destination ports, respectively, allowing the receiving device to determine which application or service should receive the data. Port numbers range from 0 to 65535, with well-known ports (e.g., port 80 for HTTP) and ephemeral ports for temporary connections.
2. **Sequence Number (32 bits):** The Sequence Number field plays a vital role in ensuring the ordered and reliable delivery of data. It assigns a unique sequence number to each segment sent, enabling the receiver to reassemble segments in the correct order.
3. **Acknowledgment Number (32 bits):** In acknowledgment-based communication, this field indicates the next sequence number the sender expects to receive from the other end. It acknowledges receipt of all data up to that number, helping to confirm successful delivery.
4. **Data Offset (4 bits):** The Data Offset field specifies the length of the TCP header in 32-bit words. This value is necessary because TCP allows for variable-length options in the header, so the receiver needs to know where the actual data begins.
5. **Reserved (6 bits):** These bits are reserved for future use and should be set to zero.
6. **Control Flags (6 bits):** TCP uses a variety of control flags to manage the connection. Key flags include:
    - `URG` (Urgent Pointer): Indicates that urgent data follows in the segment.
    - `ACK` (Acknowledgment): Acknowledges the receipt of data.
    - `PSH` (Push Function): Urges the receiver to push data to the application immediately.
    - `RST` (Reset Connection): Resets the connection in response to an error.
    - `SYN` (Synchronize Sequence Numbers): Initiates a connection.
    - `FIN` (Finish): Indicates the end of data transmission.
7. **Window Size (16 bits):** The Window Size field specifies the size of the sender's receive window, indicating the amount of data it can accept without overflowing its buffer. It helps in flow control and prevents congestion.
8. **Checksum (16 bits):** The Checksum field is used for error detection, ensuring the integrity of the TCP header and data during transmission.
9. **Urgent Pointer (16 bits):** This field is only significant if the `URG` flag is set. It points to the urgent data in the segment.
10. **Options (variable length):** The Options field allows for various TCP options, such as Maximum Segment Size (MSS), Timestamps, and Window Scale, among others, to be included in the header.

The TCP header, with its rich set of fields, provides the foundation for
reliable and orderly data transfer in network communication. By managing
sequence numbers, acknowledgments, flow control, and error checking, TCP ensures
that data reaches its destination accurately and efficiently, even in complex
and congested network environments.

### net_packet_tcp

The `net_packet_tcp` event provides one event for each existing TCP packet that
reaches or leaves one of the processes being traced (or even "all OS processes
for the default run"). As arguments for this event you will find: `src`, `dst`,
`src_port`, `dst_port`, `metadata` arguments and all `TCP header fields`.

Example:

```console
tracee --output json --events net_packet_tcp --events net_packet_tcp.args.src=fd12:3456:789a::2
```

```json
{"timestamp":1696272024347781212,"threadStartTime":1696271974944102178,"processorId":7,"processId":1107258,"cgroupId":5650,"threadId":1107258,"parentProcessId":1098248,"hostProcessId":1107258,"hostThreadId":1107258,"hostParentProcessId":1098248,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2002","eventName":"net_packet_tcp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2781367766,"processEntityId":2781367766,"parentEntityId":129643807,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::1"},{"name":"src_port","type":"u16","value":8080},{"name":"dst_port","type":"u16","value":55013},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":8080,"dstPort":55013,"seq":677659081,"ack":0,"dataOffset":5,"FIN":0,"SYN":0,"RST":1,"PSH":0,"ACK":0,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":0,"checksum":21540,"urgent":0}}]}
{"timestamp":1696272027374076813,"threadStartTime":1696272027372569306,"processorId":4,"processId":1107603,"cgroupId":5650,"threadId":1107603,"parentProcessId":1098248,"hostProcessId":1107603,"hostThreadId":1107603,"hostParentProcessId":1098248,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2002","eventName":"net_packet_tcp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2571859936,"processEntityId":2571859936,"parentEntityId":129643807,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::1"},{"name":"src_port","type":"u16","value":8080},{"name":"dst_port","type":"u16","value":49963},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":8080,"dstPort":49963,"seq":795748968,"ack":922008806,"dataOffset":10,"FIN":0,"SYN":1,"RST":0,"PSH":0,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":65464,"checksum":21560,"urgent":0}}]}
{"timestamp":1696272027906687804,"threadStartTime":1696272021882621094,"processorId":0,"processId":1107548,"cgroupId":5650,"threadId":1107548,"parentProcessId":1037836,"hostProcessId":1107548,"hostThreadId":1107548,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2002","eventName":"net_packet_tcp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"socket","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":341009752,"processEntityId":341009752,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::1"},{"name":"src_port","type":"u16","value":8080},{"name":"dst_port","type":"u16","value":49963},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":8080,"dstPort":49963,"seq":795748969,"ack":922008809,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":0,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":512,"checksum":21552,"urgent":0}}]}
{"timestamp":1696272027906697145,"threadStartTime":1696272027372569306,"processorId":0,"processId":1107603,"cgroupId":5650,"threadId":1107603,"parentProcessId":1098248,"hostProcessId":1107603,"hostThreadId":1107603,"hostParentProcessId":1098248,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2002","eventName":"net_packet_tcp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2571859936,"processEntityId":2571859936,"parentEntityId":129643807,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::1"},{"name":"src_port","type":"u16","value":8080},{"name":"dst_port","type":"u16","value":49963},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":8080,"dstPort":49963,"seq":795748969,"ack":922008809,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":0,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":512,"checksum":21552,"urgent":0}}]}
{"timestamp":1696272028900730092,"threadStartTime":1696272021882621094,"processorId":0,"processId":1107548,"cgroupId":5650,"threadId":1107548,"parentProcessId":1037836,"hostProcessId":1107548,"hostThreadId":1107548,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2002","eventName":"net_packet_tcp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"write","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":341009752,"processEntityId":341009752,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::1"},{"name":"src_port","type":"u16","value":8080},{"name":"dst_port","type":"u16","value":49963},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":8080,"dstPort":49963,"seq":795748969,"ack":922008809,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":1,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":512,"checksum":21556,"urgent":0}}]}
{"timestamp":1696272028900769370,"threadStartTime":1696272027372569306,"processorId":0,"processId":1107603,"cgroupId":5650,"threadId":1107603,"parentProcessId":1098248,"hostProcessId":1107603,"hostThreadId":1107603,"hostParentProcessId":1098248,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2002","eventName":"net_packet_tcp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2571859936,"processEntityId":2571859936,"parentEntityId":129643807,"args":[{"name":"src","type":"const char*","value":"fd12:3456:789a::2"},{"name":"dst","type":"const char*","value":"fd12:3456:789a::1"},{"name":"src_port","type":"u16","value":8080},{"name":"dst_port","type":"u16","value":49963},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":8080,"dstPort":49963,"seq":795748969,"ack":922008809,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":1,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":512,"checksum":21556,"urgent":0}}]}
```
