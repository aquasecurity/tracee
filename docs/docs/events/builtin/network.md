Tracee offers a set of network events that makes it easy to trace network activity in common protocols.

## Available network events

- [net_packet_ipv4](#net_packet_ipv4)
- [net_packet_ipv6](#net_packet_ipv6)
- [net_packet_tcp](#net_packet_tcp)
- [net_packet_udp](#net_packet_udp)
- [net_packet_icmp](#net_packet_icmp)
- [net_packet_icmpv6](#net_packet_icmpv6)
- [net_packet_dns](#net_packet_dns)
- [net_packet_dns_request](#net_packet_dns_request)
- [net_packet_dns_response](#net_packet_dns_response)

## Examples

### net_packet_ipv4

```json
# three way handshake for a TCP connection.

{"timestamp":1671040290192938971,"threadStartTime":341237880436231,"processorId":2,"processId":3120261,"cgroupId":20552,"threadId":3120261,"parentProcessId":3101489,"hostProcessId":3120261,"hostThreadId":3120261,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2007","eventName":"net_packet_ipv4","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.1"},{"name":"dst","type":"const char*","value":"10.157.254.193"},{"name":"proto_ipv4","type":"trace.ProtoIPv4","value":{"version":4,"IHL":5,"TOS":0,"length":60,"id":42857,"flags":2,"fragOffset":0,"TTL":64,"protocol":"TCP","checksum":33109,"srcIP":"10.157.254.1","dstIP":"10.157.254.193"}}]}
{"timestamp":1671040290193572748,"threadStartTime":341237880436231,"processorId":13,"processId":3120261,"cgroupId":20552,"threadId":3120261,"parentProcessId":3101489,"hostProcessId":3120261,"hostThreadId":3120261,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2007","eventName":"net_packet_ipv4","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.193"},{"name":"dst","type":"const char*","value":"10.157.254.1"},{"name":"proto_ipv4","type":"trace.ProtoIPv4","value":{"version":4,"IHL":5,"TOS":0,"length":60,"id":0,"flags":2,"fragOffset":0,"TTL":64,"protocol":"TCP","checksum":10431,"srcIP":"10.157.254.193","dstIP":"10.157.254.1"}}]}
{"timestamp":1671040290193642873,"threadStartTime":341237880436231,"processorId":13,"processId":3120261,"cgroupId":20552,"threadId":3120261,"parentProcessId":3101489,"hostProcessId":3120261,"hostThreadId":3120261,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2007","eventName":"net_packet_ipv4","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.1"},{"name":"dst","type":"const char*","value":"10.157.254.193"},{"name":"proto_ipv4","type":"trace.ProtoIPv4","value":{"version":4,"IHL":5,"TOS":0,"length":52,"id":42858,"flags":2,"fragOffset":0,"TTL":64,"protocol":"TCP","checksum":33116,"srcIP":"10.157.254.1","dstIP":"10.157.254.193"}}]}

# send a single packet and receive an ack.

{"timestamp":1671040295319879439,"threadStartTime":341237880436231,"processorId":2,"processId":3120261,"cgroupId":20552,"threadId":3120261,"parentProcessId":3101489,"hostProcessId":3120261,"hostThreadId":3120261,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2007","eventName":"net_packet_ipv4","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.1"},{"name":"dst","type":"const char*","value":"10.157.254.193"},{"name":"proto_ipv4","type":"trace.ProtoIPv4","value":{"version":4,"IHL":5,"TOS":0,"length":54,"id":42859,"flags":2,"fragOffset":0,"TTL":64,"protocol":"TCP","checksum":33113,"srcIP":"10.157.254.1","dstIP":"10.157.254.193"}}]}
{"timestamp":1671040295320501275,"threadStartTime":341237880436231,"processorId":15,"processId":3120261,"cgroupId":20552,"threadId":3120261,"parentProcessId":3101489,"hostProcessId":3120261,"hostThreadId":3120261,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2007","eventName":"net_packet_ipv4","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.193"},{"name":"dst","type":"const char*","value":"10.157.254.1"},{"name":"proto_ipv4","type":"trace.ProtoIPv4","value":{"version":4,"IHL":5,"TOS":0,"length":52,"id":56842,"flags":2,"fragOffset":0,"TTL":64,"protocol":"TCP","checksum":19132,"srcIP":"10.157.254.193","dstIP":"10.157.254.1"}}]}

# receive a single packet and send an ack.

{"timestamp":1671040299925291880,"threadStartTime":341237880436231,"processorId":5,"processId":3120261,"cgroupId":20552,"threadId":3120261,"parentProcessId":3101489,"hostProcessId":3120261,"hostThreadId":3120261,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2007","eventName":"net_packet_ipv4","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.193"},{"name":"dst","type":"const char*","value":"10.157.254.1"},{"name":"proto_ipv4","type":"trace.ProtoIPv4","value":{"version":4,"IHL":5,"TOS":0,"length":54,"id":56843,"flags":2,"fragOffset":0,"TTL":64,"protocol":"TCP","checksum":19129,"srcIP":"10.157.254.193","dstIP":"10.157.254.1"}}]}
{"timestamp":1671040299925385970,"threadStartTime":341237880436231,"processorId":5,"processId":3120261,"cgroupId":20552,"threadId":3120261,"parentProcessId":3101489,"hostProcessId":3120261,"hostThreadId":3120261,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2007","eventName":"net_packet_ipv4","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.1"},{"name":"dst","type":"const char*","value":"10.157.254.193"},{"name":"proto_ipv4","type":"trace.ProtoIPv4","value":{"version":4,"IHL":5,"TOS":0,"length":52,"id":42860,"flags":2,"fragOffset":0,"TTL":64,"protocol":"TCP","checksum":33114,"srcIP":"10.157.254.1","dstIP":"10.157.254.193"}}]}
```

### net_packet_ipv6

```json
# three way handshake for a TCP under IPv6 connection.

{"timestamp":1671041051949404378,"threadStartTime":341999636945074,"processorId":10,"processId":3141206,"cgroupId":20552,"threadId":3141206,"parentProcessId":3101489,"hostProcessId":3141206,"hostThreadId":3141206,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2008","eventName":"net_packet_ipv6","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"fd6e:a63d:71f:2000::1"},{"name":"dst","type":"const char*","value":"fd6e:a63d:71f:2000::2"},{"name":"proto_ipv6","type":"trace.ProtoIPv6","value":{"version":6,"trafficClass":0,"flowLabel":263249,"length":40,"nextHeader":"TCP","hopLimit":64,"srcIP":"fd6e:a63d:71f:2000::1","dstIP":"fd6e:a63d:71f:2000::2"}}]}
{"timestamp":1671041051950428522,"threadStartTime":341999636945074,"processorId":3,"processId":3141206,"cgroupId":20552,"threadId":3141206,"parentProcessId":3101489,"hostProcessId":3141206,"hostThreadId":3141206,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2008","eventName":"net_packet_ipv6","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"fd6e:a63d:71f:2000::2"},{"name":"dst","type":"const char*","value":"fd6e:a63d:71f:2000::1"},{"name":"proto_ipv6","type":"trace.ProtoIPv6","value":{"version":6,"trafficClass":0,"flowLabel":917337,"length":40,"nextHeader":"TCP","hopLimit":64,"srcIP":"fd6e:a63d:71f:2000::2","dstIP":"fd6e:a63d:71f:2000::1"}}]}
{"timestamp":1671041051950513760,"threadStartTime":341999636945074,"processorId":3,"processId":3141206,"cgroupId":20552,"threadId":3141206,"parentProcessId":3101489,"hostProcessId":3141206,"hostThreadId":3141206,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2008","eventName":"net_packet_ipv6","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"fd6e:a63d:71f:2000::1"},{"name":"dst","type":"const char*","value":"fd6e:a63d:71f:2000::2"},{"name":"proto_ipv6","type":"trace.ProtoIPv6","value":{"version":6,"trafficClass":0,"flowLabel":263249,"length":32,"nextHeader":"TCP","hopLimit":64,"srcIP":"fd6e:a63d:71f:2000::1","dstIP":"fd6e:a63d:71f:2000::2"}}]}

# send a single packet and receive an ack.

{"timestamp":1671041054444258140,"threadStartTime":341999636945074,"processorId":10,"processId":3141206,"cgroupId":20552,"threadId":3141206,"parentProcessId":3101489,"hostProcessId":3141206,"hostThreadId":3141206,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2008","eventName":"net_packet_ipv6","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"fd6e:a63d:71f:2000::1"},{"name":"dst","type":"const char*","value":"fd6e:a63d:71f:2000::2"},{"name":"proto_ipv6","type":"trace.ProtoIPv6","value":{"version":6,"trafficClass":0,"flowLabel":263249,"length":34,"nextHeader":"TCP","hopLimit":64,"srcIP":"fd6e:a63d:71f:2000::1","dstIP":"fd6e:a63d:71f:2000::2"}}]}
{"timestamp":1671041054444933243,"threadStartTime":341999636945074,"processorId":19,"processId":3141206,"cgroupId":20552,"threadId":3141206,"parentProcessId":3101489,"hostProcessId":3141206,"hostThreadId":3141206,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2008","eventName":"net_packet_ipv6","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"fd6e:a63d:71f:2000::2"},{"name":"dst","type":"const char*","value":"fd6e:a63d:71f:2000::1"},{"name":"proto_ipv6","type":"trace.ProtoIPv6","value":{"version":6,"trafficClass":0,"flowLabel":917337,"length":32,"nextHeader":"TCP","hopLimit":64,"srcIP":"fd6e:a63d:71f:2000::2","dstIP":"fd6e:a63d:71f:2000::1"}}]}

# receive a single packet and send an ack.

{"timestamp":1671041058522081844,"threadStartTime":341999636945074,"processorId":3,"processId":3141206,"cgroupId":20552,"threadId":3141206,"parentProcessId":3101489,"hostProcessId":3141206,"hostThreadId":3141206,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2008","eventName":"net_packet_ipv6","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"fd6e:a63d:71f:2000::2"},{"name":"dst","type":"const char*","value":"fd6e:a63d:71f:2000::1"},{"name":"proto_ipv6","type":"trace.ProtoIPv6","value":{"version":6,"trafficClass":0,"flowLabel":917337,"length":34,"nextHeader":"TCP","hopLimit":64,"srcIP":"fd6e:a63d:71f:2000::2","dstIP":"fd6e:a63d:71f:2000::1"}}]}
{"timestamp":1671041058522149062,"threadStartTime":341999636945074,"processorId":3,"processId":3141206,"cgroupId":20552,"threadId":3141206,"parentProcessId":3101489,"hostProcessId":3141206,"hostThreadId":3141206,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2008","eventName":"net_packet_ipv6","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"fd6e:a63d:71f:2000::1"},{"name":"dst","type":"const char*","value":"fd6e:a63d:71f:2000::2"},{"name":"proto_ipv6","type":"trace.ProtoIPv6","value":{"version":6,"trafficClass":0,"flowLabel":263249,"length":32,"nextHeader":"TCP","hopLimit":64,"srcIP":"fd6e:a63d:71f:2000::1","dstIP":"fd6e:a63d:71f:2000::2"}}]}
```

### net_packet_tcp

```json
# three way handshake for the tcp connection (note SYN and ACK flags).

{"timestamp":1671041571396216462,"threadStartTime":342519082935538,"processorId":12,"processId":3156273,"cgroupId":20552,"threadId":3156273,"parentProcessId":3101489,"hostProcessId":3156273,"hostThreadId":3156273,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2009","eventName":"net_packet_tcp","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.1"},{"name":"dst","type":"const char*","value":"10.157.254.193"},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":51594,"dstPort":8090,"seq":1188220445,"ack":0,"dataOffset":10,"FIN":0,"SYN":1,"RST":0,"PSH":0,"ACK":0,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":64240,"checksum":4652,"urgent":0}}]}
{"timestamp":1671041571397219944,"threadStartTime":342519082935538,"processorId":1,"processId":3156273,"cgroupId":20552,"threadId":3156273,"parentProcessId":3101489,"hostProcessId":3156273,"hostThreadId":3156273,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2009","eventName":"net_packet_tcp","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.193"},{"name":"dst","type":"const char*","value":"10.157.254.1"},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":8090,"dstPort":51594,"seq":658038831,"ack":1188220446,"dataOffset":10,"FIN":0,"SYN":1,"RST":0,"PSH":0,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":65160,"checksum":4652,"urgent":0}}]}
{"timestamp":1671041571397303639,"threadStartTime":342519082935538,"processorId":1,"processId":3156273,"cgroupId":20552,"threadId":3156273,"parentProcessId":3101489,"hostProcessId":3156273,"hostThreadId":3156273,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2009","eventName":"net_packet_tcp","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.1"},{"name":"dst","type":"const char*","value":"10.157.254.193"},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":51594,"dstPort":8090,"seq":1188220446,"ack":658038832,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":0,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":502,"checksum":4644,"urgent":0}}]}

# send a single packet and receive an ack for the sequence.

{"timestamp":1671041574116624540,"threadStartTime":342519082935538,"processorId":20,"processId":3156273,"cgroupId":20552,"threadId":3156273,"parentProcessId":3101489,"hostProcessId":3156273,"hostThreadId":3156273,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2009","eventName":"net_packet_tcp","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.1"},{"name":"dst","type":"const char*","value":"10.157.254.193"},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":51594,"dstPort":8090,"seq":1188220446,"ack":658038832,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":1,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":502,"checksum":4646,"urgent":0}}]}
{"timestamp":1671041574117560789,"threadStartTime":342519082935538,"processorId":21,"processId":3156273,"cgroupId":20552,"threadId":3156273,"parentProcessId":3101489,"hostProcessId":3156273,"hostThreadId":3156273,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2009","eventName":"net_packet_tcp","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.193"},{"name":"dst","type":"const char*","value":"10.157.254.1"},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":8090,"dstPort":51594,"seq":658038832,"ack":1188220448,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":0,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":510,"checksum":4644,"urgent":0}}]}

# receive a single packet and send an ack for the sequence.

{"timestamp":1671041577684649596,"threadStartTime":342519082935538,"processorId":0,"processId":3156273,"cgroupId":20552,"threadId":3156273,"parentProcessId":3101489,"hostProcessId":3156273,"hostThreadId":3156273,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2009","eventName":"net_packet_tcp","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.193"},{"name":"dst","type":"const char*","value":"10.157.254.1"},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":8090,"dstPort":51594,"seq":658038832,"ack":1188220448,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":1,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":510,"checksum":4646,"urgent":0}}]}
{"timestamp":1671041577684705270,"threadStartTime":342519082935538,"processorId":0,"processId":3156273,"cgroupId":20552,"threadId":3156273,"parentProcessId":3101489,"hostProcessId":3156273,"hostThreadId":3156273,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2009","eventName":"net_packet_tcp","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.1"},{"name":"dst","type":"const char*","value":"10.157.254.193"},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":51594,"dstPort":8090,"seq":1188220448,"ack":658038834,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":0,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":502,"checksum":4644,"urgent":0}}]}
```

### net_packet_udp

```json
# send a single packet.

{"timestamp":1671041745559197126,"threadStartTime":342691388187456,"processorId":15,"processId":3160590,"cgroupId":20552,"threadId":3160590,"parentProcessId":3101489,"hostProcessId":3160590,"hostThreadId":3160590,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2010","eventName":"net_packet_udp","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.1"},{"name":"dst","type":"const char*","value":"10.157.254.193"},{"name":"proto_udp","type":"trace.ProtoUDP","value":{"srcPort":54370,"dstPort":8090,"length":10,"checksum":4633}}]}

# receive a single packet.

{"timestamp":1671041746569025030,"threadStartTime":342691388187456,"processorId":5,"processId":3160590,"cgroupId":20552,"threadId":3160590,"parentProcessId":3101489,"hostProcessId":3160590,"hostThreadId":3160590,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"nc","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2010","eventName":"net_packet_udp","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.193"},{"name":"dst","type":"const char*","value":"10.157.254.1"},{"name":"proto_udp","type":"trace.ProtoUDP","value":{"srcPort":8090,"dstPort":54370,"length":10,"checksum":4633}}]}
```

### net_packet_icmp

```json
# send an ICMP echo request.

{"timestamp":1671041834556860509,"threadStartTime":342782244688605,"processorId":0,"processId":3162824,"cgroupId":20552,"threadId":3162824,"parentProcessId":3101489,"hostProcessId":3162824,"hostThreadId":3162824,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"ping","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2011","eventName":"net_packet_icmp","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.1"},{"name":"dst","type":"const char*","value":"10.157.254.193"},{"name":"proto_icmp","type":"trace.ProtoICMP","value":{"typeCode":"EchoRequest","checksum":1592,"id":27646,"seq":1}}]}

# receive an ICMP echo reply.

{"timestamp":1671041834557721951,"threadStartTime":342782244688605,"processorId":13,"processId":3162824,"cgroupId":20552,"threadId":3162824,"parentProcessId":3101489,"hostProcessId":3162824,"hostThreadId":3162824,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"ping","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2011","eventName":"net_packet_icmp","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"10.157.254.193"},{"name":"dst","type":"const char*","value":"10.157.254.1"},{"name":"proto_icmp","type":"trace.ProtoICMP","value":{"typeCode":"EchoReply","checksum":3640,"id":27646,"seq":1}}]}
```

### net_packet_icmpv6

```json
# send an ICMPv6 echo request.

{"timestamp":1671041966651955456,"threadStartTime":342914339316549,"processorId":13,"processId":3166608,"cgroupId":20552,"threadId":3166608,"parentProcessId":3101489,"hostProcessId":3166608,"hostThreadId":3166608,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"ping","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2012","eventName":"net_packet_icmpv6","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"fd6e:a63d:71f:2000::1"},{"name":"dst","type":"const char*","value":"fd6e:a63d:71f:2000::2"},{"name":"proto_icmpv6","type":"trace.ProtoICMPv6","value":{"typeCode":"EchoRequest","checksum":25099}}]}

# receive an ICMPv6 echo reply.

{"timestamp":1671041966653079084,"threadStartTime":342914339316549,"processorId":3,"processId":3166608,"cgroupId":20552,"threadId":3166608,"parentProcessId":3101489,"hostProcessId":3166608,"hostThreadId":3166608,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"ping","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2012","eventName":"net_packet_icmpv6","argsNum":3,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"fd6e:a63d:71f:2000::2"},{"name":"dst","type":"const char*","value":"fd6e:a63d:71f:2000::1"},{"name":"proto_icmpv6","type":"trace.ProtoICMPv6","value":{"typeCode":"EchoReply","checksum":24843}}]}
```

### net_packet_dns

```json
# query type=A from nslookup to local systemd-resolved.

{"timestamp":1671042316117498783,"threadStartTime":343263806334087,"processorId":7,"processId":3179904,"cgroupId":20552,"threadId":3179905,"parentProcessId":3101489,"hostProcessId":3179904,"hostThreadId":3179905,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"isc-net-0000","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2013","eventName":"net_packet_dns","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"127.0.0.1"},{"name":"dst","type":"const char*","value":"127.0.0.53"},{"name":"src_port","type":"u16","value":42752},{"name":"dst_port","type":"u16","value":53},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":52902,"QR":0,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":0,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":0,"NSCount":0,"ARCount":0,"questions":[{"name":"www.uol.com.br","type":"A","class":"IN"}],"answers":[],"authorities":[],"additionals":[]}}]}

# response from systemd-resolved to nslookup (after querying default nameserver).
# response contains original query and multiple answers to the query.

{"timestamp":1671042316131226611,"threadStartTime":343263806334087,"processorId":10,"processId":3179904,"cgroupId":20552,"threadId":3179905,"parentProcessId":3101489,"hostProcessId":3179904,"hostThreadId":3179905,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"isc-net-0000","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2013","eventName":"net_packet_dns","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"127.0.0.53"},{"name":"dst","type":"const char*","value":"127.0.0.1"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":42752},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":52902,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":5,"NSCount":0,"ARCount":0,"questions":[{"name":"www.uol.com.br","type":"A","class":"IN"}],"answers":[{"name":"www.uol.com.br","type":"CNAME","class":"IN","TTL":43,"IP":"","NS":"","CNAME":"dftex7xfha8fh.cloudfront.net","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"dftex7xfha8fh.cloudfront.net","type":"A","class":"IN","TTL":55,"IP":"65.8.214.126","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"dftex7xfha8fh.cloudfront.net","type":"A","class":"IN","TTL":55,"IP":"65.8.214.78","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"dftex7xfha8fh.cloudfront.net","type":"A","class":"IN","TTL":55,"IP":"65.8.214.70","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"dftex7xfha8fh.cloudfront.net","type":"A","class":"IN","TTL":55,"IP":"65.8.214.49","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"authorities":[],"additionals":[]}}]}

# query type=MX from nslookup to local systemd-resolved.

{"timestamp":1671042491079309907,"threadStartTime":343438768169717,"processorId":1,"processId":3183907,"cgroupId":20552,"threadId":3183908,"parentProcessId":3101489,"hostProcessId":3183907,"hostThreadId":3183908,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"isc-net-0000","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2013","eventName":"net_packet_dns","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"127.0.0.1"},{"name":"dst","type":"const char*","value":"127.0.0.53"},{"name":"src_port","type":"u16","value":34981},{"name":"dst_port","type":"u16","value":53},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":33920,"QR":0,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":0,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":0,"NSCount":0,"ARCount":0,"questions":[{"name":"uol.com.br","type":"MX","class":"IN"}],"answers":[],"authorities":[],"additionals":[]}}]}

# response from systemd-resolved to nslookup containing original MX query and the MX answer.

{"timestamp":1671042491090381166,"threadStartTime":343438768169717,"processorId":10,"processId":3183907,"cgroupId":20552,"threadId":3183908,"parentProcessId":3101489,"hostProcessId":3183907,"hostThreadId":3183908,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"isc-net-0000","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2013","eventName":"net_packet_dns","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"127.0.0.53"},{"name":"dst","type":"const char*","value":"127.0.0.1"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":34981},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":33920,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":1,"NSCount":0,"ARCount":0,"questions":[{"name":"uol.com.br","type":"MX","class":"IN"}],"answers":[{"name":"uol.com.br","type":"MX","class":"IN","TTL":17618,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":10,"name":"mx.uol.com.br"},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"authorities":[],"additionals":[]}}]}
```

### net_packet_dns_request

```json
# query type=A from nslookup to local systemd-resolved.
# this event does not contain all DNS header fields as the net_packet_dns does.

{"timestamp":1671043215487322928,"threadStartTime":344163176158597,"processorId":5,"processId":3200575,"cgroupId":20552,"threadId":3200576,"parentProcessId":3101489,"hostProcessId":3200575,"hostThreadId":3200576,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"isc-net-0000","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2014","eventName":"net_packet_dns_request","argsNum":2,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"127.0.0.1","dst_ip":"127.0.0.53","src_port":46259,"dst_port":53,"protocol":17,"packet_len":60,"iface":"any"}},{"name":"dns_questions","type":"[]trace.DnsQueryData","value":[{"query":"www.uol.com.br","query_type":"A","query_class":"IN"}]}]}
{"timestamp":1671043215503932068,"threadStartTime":344163176158597,"processorId":10,"processId":3200575,"cgroupId":20552,"threadId":3200576,"parentProcessId":3101489,"hostProcessId":3200575,"hostThreadId":3200576,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"isc-net-0000","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2014","eventName":"net_packet_dns_request","argsNum":2,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"127.0.0.53","dst_ip":"127.0.0.1","src_port":53,"dst_port":46259,"protocol":17,"packet_len":166,"iface":"any"}},{"name":"dns_questions","type":"[]trace.DnsQueryData","value":[{"query":"www.uol.com.br","query_type":"A","query_class":"IN"}]}]}
```

!!! Attention Warning
    The `net_packet_dns_request` event is an event that is backwards compatible with an existing event called `dns_request`. The intention to have such event is to allow existing signatures already relying in the `dns_request` event, to rely in the new `net_packet_dns_request`. The benefit for the new event is that, differently from the `dns_request` event, there is no need to set an interface to monitor events when monitoring `net_packet_dns_request`. It gets DNS events from all existing interfaces and filters applied.

!!! Important
    This event might be deprecated or have its argument types changed in future versions.

### net_packet_response

```json
# response from systemd-resolved to nslookup (after querying default nameserver).
# response contains original query and multiple answers to the query.
# this event does not contain all DNS header fields as the net_packet_dns does.

{"timestamp":1671043317719969041,"threadStartTime":344265391016498,"processorId":10,"processId":3203040,"cgroupId":20552,"threadId":3203041,"parentProcessId":3101489,"hostProcessId":3203040,"hostThreadId":3203041,"hostParentProcessId":3101489,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"isc-net-0000","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2015","eventName":"net_packet_dns_response","argsNum":2,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"127.0.0.53","dst_ip":"127.0.0.1","src_port":53,"dst_port":41373,"protocol":17,"packet_len":166,"iface":"any"}},{"name":"dns_response","type":"[]trace.DnsResponseData","value":[{"query_data":{"query":"www.uol.com.br","query_type":"A","query_class":"IN"},"dns_answer":[{"answer_type":"CNAME","ttl":22,"answer":"dftex7xfha8fh.cloudfront.net"},{"answer_type":"A","ttl":60,"answer":"65.8.214.126"},{"answer_type":"A","ttl":60,"answer":"65.8.214.70"},{"answer_type":"A","ttl":60,"answer":"65.8.214.49"},{"answer_type":"A","ttl":60,"answer":"65.8.214.78"}]}]}]}
```

!!! Attention Warning
    The `net_packet_dns_response` event is an event that is backwards compatible with an existing event called `dns_response`. The intention to have such event is to allow existing signatures already relying in the `dns_response` event, to rely in the new `net_packet_dns_response`. The benefit for the new event is that, differently from the `dns_response` event, there is no need to set an interface to monitor events when monitoring `net_packet_dns_response`. It gets DNS events from all existing interfaces and filters applied.

!!! Important
    This event might be deprecated or have its argument types changed in future versions.

## Network Event Filtering

!!! Supported Attention
    For now it is **NOT** possible to filter the events through the
    header fields, but it **IS** possible, and recommended, to filter
    the events through **`src`**, **`dest`** fields. Not filtering
    network events might be hard to consume because of the amount of
    traced events.

Trace all TCP packets sent to port 80 anywhere, from any process:

```console
tracee --output json --filter event=net_packet_tcp --filter net_packet_tcp.args.dst_port=80
```

```json
{"timestamp":1671149983169847976,"threadStartTime":450930828307685,"processorId":22,"processId":1284215,"cgroupId":27149,"threadId":1284215,"parentProcessId":1268815,"hostProcessId":1284215,"hostThreadId":1284215,"hostParentProcessId":1268815,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"w3m","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2009","eventName":"net_packet_tcp","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"192.168.100.2"},{"name":"dst","type":"const char*","value":"200.147.3.157"},{"name":"src_port","type":"u16","value":46594},{"name":"dst_port","type":"u16","value":80},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":46594,"dstPort":80,"seq":3415564579,"ack":0,"dataOffset":10,"FIN":0,"SYN":1,"RST":0,"PSH":0,"ACK":0,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":64240,"checksum":61705,"urgent":0}}]}
{"timestamp":1671149983178147951,"threadStartTime":450930828307685,"processorId":23,"processId":1284215,"cgroupId":27149,"threadId":1284215,"parentProcessId":1268815,"hostProcessId":1284215,"hostThreadId":1284215,"hostParentProcessId":1268815,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"w3m","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2009","eventName":"net_packet_tcp","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"192.168.100.2"},{"name":"dst","type":"const char*","value":"200.147.3.157"},{"name":"src_port","type":"u16","value":46594},{"name":"dst_port","type":"u16","value":80},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":46594,"dstPort":80,"seq":3415564580,"ack":1519583696,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":0,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":502,"checksum":61697,"urgent":0}}]}
{"timestamp":1671149983178263829,"threadStartTime":450930828307685,"processorId":22,"processId":1284215,"cgroupId":27149,"threadId":1284215,"parentProcessId":1268815,"hostProcessId":1284215,"hostThreadId":1284215,"hostParentProcessId":1268815,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"w3m","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2009","eventName":"net_packet_tcp","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"192.168.100.2"},{"name":"dst","type":"const char*","value":"200.147.3.157"},{"name":"src_port","type":"u16","value":46594},{"name":"dst_port","type":"u16","value":80},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":46594,"dstPort":80,"seq":3415564580,"ack":1519583696,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":1,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":502,"checksum":61907,"urgent":0}}]}
```

Trace all DNS packets received ONLY from Google DNS server '8.8.8.8':

```console
tracee --output json --filter event=net_packet_dns --filter net_packet_dns.args.src=8.8.8.8
```

(only **systemd-resolved**, since all the other processes are resolving using local systemd-resolved server `127.0.1.1:53`):

```json
{"timestamp":1671044490960363328,"threadStartTime":17862285588,"processorId":5,"processId":1016,"cgroupId":2847,"threadId":1016,"parentProcessId":1,"hostProcessId":1016,"hostThreadId":1016,"hostParentProcessId":1,"userId":104,"mountNamespace":4026533212,"pidNamespace":4026531836,"processName":"systemd-resolve","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2013","eventName":"net_packet_dns","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"8.8.8.8"},{"name":"dst","type":"const char*","value":"192.168.100.2"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":57278},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":45141,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":0,"NSCount":1,"ARCount":1,"questions":[{"name":"github.com","type":"AAAA","class":"IN"}],"answers":[],"authorities":[{"name":"github.com","type":"SOA","class":"IN","TTL":2,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"ns-1707.awsdns-21.co.uk","RName":"awsdns-hostmaster.amazon.com","serial":1,"refresh":7200,"retry":900,"expire":1209600,"minimum":86400},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"additionals":[{"name":"","type":"OPT","class":"Unknown","TTL":0,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}]}}]}
{"timestamp":1671044491458692167,"threadStartTime":17862285588,"processorId":5,"processId":1016,"cgroupId":2847,"threadId":1016,"parentProcessId":1,"hostProcessId":1016,"hostThreadId":1016,"hostParentProcessId":1,"userId":104,"mountNamespace":4026533212,"pidNamespace":4026531836,"processName":"systemd-resolve","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2013","eventName":"net_packet_dns","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"8.8.8.8"},{"name":"dst","type":"const char*","value":"192.168.100.2"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":44834},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":60536,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":1,"NSCount":0,"ARCount":1,"questions":[{"name":"github.com","type":"A","class":"IN"}],"answers":[{"name":"github.com","type":"A","class":"IN","TTL":60,"IP":"20.201.28.151","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"authorities":[],"additionals":[{"name":"","type":"OPT","class":"Unknown","TTL":0,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}]}}]}
{"timestamp":1671044592138383113,"threadStartTime":17862285588,"processorId":5,"processId":1016,"cgroupId":2847,"threadId":1016,"parentProcessId":1,"hostProcessId":1016,"hostThreadId":1016,"hostParentProcessId":1,"userId":104,"mountNamespace":4026533212,"pidNamespace":4026531836,"processName":"systemd-resolve","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2013","eventName":"net_packet_dns","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"8.8.8.8"},{"name":"dst","type":"const char*","value":"192.168.100.2"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":44265},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":22103,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":1,"NSCount":0,"ARCount":1,"questions":[{"name":"github.com","type":"A","class":"IN"}],"answers":[{"name":"github.com","type":"A","class":"IN","TTL":60,"IP":"20.201.28.151","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"authorities":[],"additionals":[{"name":"","type":"OPT","class":"Unknown","TTL":0,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}]}}]}
{"timestamp":1671044592139849906,"threadStartTime":17862285588,"processorId":5,"processId":1016,"cgroupId":2847,"threadId":1016,"parentProcessId":1,"hostProcessId":1016,"hostThreadId":1016,"hostParentProcessId":1,"userId":104,"mountNamespace":4026533212,"pidNamespace":4026531836,"processName":"systemd-resolve","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2013","eventName":"net_packet_dns","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"8.8.8.8"},{"name":"dst","type":"const char*","value":"192.168.100.2"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":53099},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":55518,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":0,"NSCount":1,"ARCount":1,"questions":[{"name":"github.com","type":"AAAA","class":"IN"}],"answers":[],"authorities":[{"name":"github.com","type":"SOA","class":"IN","TTL":398,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"ns-1707.awsdns-21.co.uk","RName":"awsdns-hostmaster.amazon.com","serial":1,"refresh":7200,"retry":900,"expire":1209600,"minimum":86400},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"additionals":[{"name":"","type":"OPT","class":"Unknown","TTL":0,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}]}}]}
{"timestamp":1671044593058863894,"threadStartTime":17862285588,"processorId":5,"processId":1016,"cgroupId":2847,"threadId":1016,"parentProcessId":1,"hostProcessId":1016,"hostThreadId":1016,"hostParentProcessId":1,"userId":104,"mountNamespace":4026533212,"pidNamespace":4026531836,"processName":"systemd-resolve","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2013","eventName":"net_packet_dns","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"8.8.8.8"},{"name":"dst","type":"const char*","value":"192.168.100.2"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":51112},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":64479,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":2,"NSCount":0,"ARCount":1,"questions":[{"name":"star-actions-githubusercontent-com.l-0007.l-msedge.net","type":"AAAA","class":"IN"}],"answers":[{"name":"star-actions-githubusercontent-com.l-0007.l-msedge.net","type":"CNAME","class":"IN","TTL":149,"IP":"","NS":"","CNAME":"l-0007.l-msedge.net","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"l-0007.l-msedge.net","type":"AAAA","class":"IN","TTL":149,"IP":"2620:1ec:21::16","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"authorities":[],"additionals":[{"name":"","type":"OPT","class":"Unknown","TTL":0,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}]}}]}
{"timestamp":1671044593059043810,"threadStartTime":17862285588,"processorId":5,"processId":1016,"cgroupId":2847,"threadId":1016,"parentProcessId":1,"hostProcessId":1016,"hostThreadId":1016,"hostParentProcessId":1,"userId":104,"mountNamespace":4026533212,"pidNamespace":4026531836,"processName":"systemd-resolve","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2013","eventName":"net_packet_dns","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"8.8.8.8"},{"name":"dst","type":"const char*","value":"192.168.100.2"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":51952},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":4355,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":1,"NSCount":0,"ARCount":1,"questions":[{"name":"l-0007.l-msedge.net","type":"AAAA","class":"IN"}],"answers":[{"name":"l-0007.l-msedge.net","type":"AAAA","class":"IN","TTL":105,"IP":"2620:1ec:21::16","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"authorities":[],"additionals":[{"name":"","type":"OPT","class":"Unknown","TTL":0,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}]}}]}
{"timestamp":1671044594595474660,"threadStartTime":17862285588,"processorId":5,"processId":1016,"cgroupId":2847,"threadId":1016,"parentProcessId":1,"hostProcessId":1016,"hostThreadId":1016,"hostParentProcessId":1,"userId":104,"mountNamespace":4026533212,"pidNamespace":4026531836,"processName":"systemd-resolve","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2013","eventName":"net_packet_dns","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"8.8.8.8"},{"name":"dst","type":"const char*","value":"192.168.100.2"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":57386},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":50508,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":3,"NSCount":0,"ARCount":1,"questions":[{"name":"pipelines.actions.githubusercontent.com","type":"A","class":"IN"}],"answers":[{"name":"pipelines.actions.githubusercontent.com","type":"CNAME","class":"IN","TTL":3395,"IP":"","NS":"","CNAME":"star-actions-githubusercontent-com.l-0007.l-msedge.net","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"star-actions-githubusercontent-com.l-0007.l-msedge.net","type":"CNAME","class":"IN","TTL":35,"IP":"","NS":"","CNAME":"l-0007.l-msedge.net","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"l-0007.l-msedge.net","type":"A","class":"IN","TTL":35,"IP":"13.107.42.16","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"authorities":[],"additionals":[{"name":"","type":"OPT","class":"Unknown","TTL":0,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}]}}]}
{"timestamp":1671044594596611226,"threadStartTime":17862285588,"processorId":5,"processId":1016,"cgroupId":2847,"threadId":1016,"parentProcessId":1,"hostProcessId":1016,"hostThreadId":1016,"hostParentProcessId":1,"userId":104,"mountNamespace":4026533212,"pidNamespace":4026531836,"processName":"systemd-resolve","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2013","eventName":"net_packet_dns","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"8.8.8.8"},{"name":"dst","type":"const char*","value":"192.168.100.2"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":47545},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":44968,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":3,"NSCount":0,"ARCount":1,"questions":[{"name":"pipelines.actions.githubusercontent.com","type":"AAAA","class":"IN"}],"answers":[{"name":"pipelines.actions.githubusercontent.com","type":"CNAME","class":"IN","TTL":2771,"IP":"","NS":"","CNAME":"star-actions-githubusercontent-com.l-0007.l-msedge.net","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"star-actions-githubusercontent-com.l-0007.l-msedge.net","type":"CNAME","class":"IN","TTL":115,"IP":"","NS":"","CNAME":"l-0007.l-msedge.net","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"l-0007.l-msedge.net","type":"AAAA","class":"IN","TTL":119,"IP":"2620:1ec:21::16","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"authorities":[],"additionals":[{"name":"","type":"OPT","class":"Unknown","TTL":0,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}]}}]}
{"timestamp":1671044595955957557,"threadStartTime":17862285588,"processorId":5,"processId":1016,"cgroupId":2847,"threadId":1016,"parentProcessId":1,"hostProcessId":1016,"hostThreadId":1016,"hostParentProcessId":1,"userId":104,"mountNamespace":4026533212,"pidNamespace":4026531836,"processName":"systemd-resolve","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2013","eventName":"net_packet_dns","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"8.8.8.8"},{"name":"dst","type":"const char*","value":"192.168.100.2"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":42588},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":46878,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":1,"NSCount":0,"ARCount":1,"questions":[{"name":"mx.uol.com.br","type":"A","class":"IN"}],"answers":[{"name":"mx.uol.com.br","type":"A","class":"IN","TTL":21233,"IP":"200.147.41.231","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"authorities":[],"additionals":[{"name":"","type":"OPT","class":"Unknown","TTL":0,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}]}}]}
{"timestamp":1671044595958021940,"threadStartTime":17862285588,"processorId":5,"processId":1016,"cgroupId":2847,"threadId":1016,"parentProcessId":1,"hostProcessId":1016,"hostThreadId":1016,"hostParentProcessId":1,"userId":104,"mountNamespace":4026533212,"pidNamespace":4026531836,"processName":"systemd-resolve","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"2013","eventName":"net_packet_dns","argsNum":5,"returnValue":0,"stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"src","type":"const char*","value":"8.8.8.8"},{"name":"dst","type":"const char*","value":"192.168.100.2"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":57033},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":61528,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":1,"NSCount":0,"ARCount":1,"questions":[{"name":"mx.uol.com.br","type":"A","class":"IN"}],"answers":[{"name":"mx.uol.com.br","type":"A","class":"IN","TTL":20920,"IP":"200.147.41.231","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"authorities":[],"additionals":[{"name":"","type":"OPT","class":"Unknown","TTL":0,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}]}}]}
```

## Network Based Signatures

It is possible to create Golang (or Rego) signatures for the network events. If you haven't read about how to create signatures, do it [HERE](../../detecting/golang/).

!!! Examples Note
    Below is an example of how to create a signature for the `net_packet_dns` event. This same example is used by Tracee CI/CD tests and can be found at the [GitHub repository](https://github.com/aquasecurity/tracee/tree/main/tests/e2e-net-signatures), together with some other signatures for the network events.

1. **net_packet_dns** signature example

```golang
package main

import (
    "fmt"
    "strings"

    "github.com/aquasecurity/tracee/signatures/helpers"
    "github.com/aquasecurity/tracee/types/detect"
    "github.com/aquasecurity/tracee/types/protocol"
    "github.com/aquasecurity/tracee/types/trace"
)

//
// HOWTO: The way to trigger this test signature is to execute:
//
//        nslookup -type=mx uol.com.br      and then
//        nslookup -type=ns uol.com.br      and then
//        nslookup -type=soa uol.com.br     and then
//        nslookup -type=txt uol.com.br
//
//        This will cause it trigger once and reset it status.

type e2eDNS struct {
    foundMX   bool
    foundNS   bool
    foundSOA  bool
    foundTXTs bool
    cb        detect.SignatureHandler
}

func (sig *e2eDNS) Init(cb detect.SignatureHandler) error {
    sig.cb = cb
    sig.foundMX = false   // proforma
    sig.foundNS = false   // proforma
    sig.foundSOA = false  // proforma
    sig.foundTXTs = false // proforma
    return nil
}

func (sig *e2eDNS) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "DNS",
        Version:     "0.1.0",
        Name:        "Network DNS Test",
        Description: "Network E2E Tests: DNS",
        Tags:        []string{"e2e", "network"},
    }, nil
}

func (sig *e2eDNS) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "net_packet_dns"},
    }, nil
}

func (sig *e2eDNS) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    if !ok {
        return fmt.Errorf("failed to cast event's payload")
    }

    if eventObj.EventName == "net_packet_dns" {
        dns, err := helpers.GetProtoDNSByName(eventObj, "proto_dns")
        if err != nil {
            return err
        }

        if len(dns.Answers) > 0 {
            for _, answer := range dns.Answers {
                // check if MX works
                if answer.MX.Name == "mx.uol.com.br" && answer.MX.Preference == 10 {
                    sig.foundMX = true
                }
                // check if NS works
                if answer.NS == "eliot.uol.com.br" {
                    sig.foundNS = true
                }
                // check if SOA works
                if answer.SOA.RName == "root.uol.com.br" {
                    sig.foundSOA = true
                }
                // check if TXTs works
                if answer.TXTs != nil && len(answer.TXTs) > 0 {
                    for _, txt := range answer.TXTs {
                        if strings.Contains(txt, "spf.uol.com.br") {
                            sig.foundTXTs = true
                        }
                    }
                }
            }
        }

        if !sig.foundMX || !sig.foundNS || !sig.foundSOA || !sig.foundTXTs {
            return nil
        }

        if sig.foundMX && sig.foundNS && sig.foundSOA && sig.foundTXTs { // reset signature state
            sig.foundMX = false
            sig.foundNS = false
            sig.foundSOA = false
            sig.foundTXTs = false
        }

        m, _ := sig.GetMetadata()

        sig.cb(detect.Finding{
            SigMetadata: m,
            Event:       event,
            Data:        map[string]interface{}{},
        })
    }

    return nil
}

func (sig *e2eDNS) OnSignal(s detect.Signal) error {
    return nil
}

func (sig *e2eDNS) Close() {}
```
