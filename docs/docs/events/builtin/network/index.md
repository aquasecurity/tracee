Tracee offers a set of network events that makes it easy to trace network
activity in common protocols.

## Available network events

- [net_packet_ipv4](./net_packet_ipv4.md)
- [net_packet_ipv6](./net_packet_ipv6.md)
- [net_packet_tcp](./net_packet_tcp.md)
- [net_packet_udp](./net_packet_udp.md)
- [net_packet_icmp](./net_packet_icmp.md)
- [net_packet_icmpv6](./net_packet_icmpv6.md)
- [net_packet_dns](./net_packet_dns.md)
- [net_packet_dns_request](./net_packet_dns_request.md)
- [net_packet_dns_response](./net_packet_dns_response.md)
- [net_packet_http](./net_packet_http.md)
- [net_packet_http_request](./net_packet_http_request.md)
- [net_packet_http_response](./net_packet_http_response.md)

## Network Event Filtering

!!! Supported Attention
    For now it is **NOT** possible to filter the events through the
    header fields, but it **IS** possible, and recommended, to filter
    the events through **`src`**, **`dest`** fields. Not filtering
    network events might be hard to consume because of the amount of
    traced events.

Trace all TCP packets sent to port 80 anywhere, from any process:

```console
tracee --output json --events net_packet_tcp.data.dst_port=80
```

```json
{"timestamp":1696255674450496178,"threadStartTime":1696249856019516599,"processorId":6,"processId":1014858,"cgroupId":5650,"threadId":1014989,"parentProcessId":1729,"hostProcessId":1014858,"hostThreadId":1014989,"hostParentProcessId":1729,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"vlc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2002","eventName":"net_packet_tcp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"recvmsg","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":3489249124,"processEntityId":3999221038,"parentEntityId":3069802613,"args":[{"name":"src","type":"const char*","value":"192.168.200.50"},{"name":"dst","type":"const char*","value":"70.42.73.30"},{"name":"src_port","type":"u16","value":40020},{"name":"dst_port","type":"u16","value":80},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":40020,"dstPort":80,"seq":4173220235,"ack":2867625954,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":0,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":2766,"checksum":6218,"urgent":0}}]}
{"timestamp":1696255674454872352,"threadStartTime":1696249856019516599,"processorId":6,"processId":1014858,"cgroupId":5650,"threadId":1014989,"parentProcessId":1729,"hostProcessId":1014858,"hostThreadId":1014989,"hostParentProcessId":1729,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"vlc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2002","eventName":"net_packet_tcp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"recvmsg","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":3489249124,"processEntityId":3999221038,"parentEntityId":3069802613,"args":[{"name":"src","type":"const char*","value":"192.168.200.50"},{"name":"dst","type":"const char*","value":"70.42.73.30"},{"name":"src_port","type":"u16","value":40020},{"name":"dst_port","type":"u16","value":80},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":40020,"dstPort":80,"seq":4173220235,"ack":2867626999,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":0,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":2766,"checksum":6218,"urgent":0}}]}
{"timestamp":1696255674459439720,"threadStartTime":1696249856019516599,"processorId":6,"processId":1014858,"cgroupId":5650,"threadId":1014989,"parentProcessId":1729,"hostProcessId":1014858,"hostThreadId":1014989,"hostParentProcessId":1729,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"vlc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2002","eventName":"net_packet_tcp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"recvmsg","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":3489249124,"processEntityId":3999221038,"parentEntityId":3069802613,"args":[{"name":"src","type":"const char*","value":"192.168.200.50"},{"name":"dst","type":"const char*","value":"70.42.73.30"},{"name":"src_port","type":"u16","value":40020},{"name":"dst_port","type":"u16","value":80},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":40020,"dstPort":80,"seq":4173220235,"ack":2867628044,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":0,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":2766,"checksum":6218,"urgent":0}}]}
{"timestamp":1696255674459993274,"threadStartTime":1696249856019516599,"processorId":6,"processId":1014858,"cgroupId":5650,"threadId":1014989,"parentProcessId":1729,"hostProcessId":1014858,"hostThreadId":1014989,"hostParentProcessId":1729,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"vlc","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2002","eventName":"net_packet_tcp","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"recvmsg","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":3489249124,"processEntityId":3999221038,"parentEntityId":3069802613,"args":[{"name":"src","type":"const char*","value":"192.168.200.50"},{"name":"dst","type":"const char*","value":"70.42.73.30"},{"name":"src_port","type":"u16","value":40020},{"name":"dst_port","type":"u16","value":80},{"name":"proto_tcp","type":"trace.ProtoTCP","value":{"srcPort":40020,"dstPort":80,"seq":4173220235,"ack":2867629089,"dataOffset":8,"FIN":0,"SYN":0,"RST":0,"PSH":0,"ACK":1,"URG":0,"ECE":0,"CWR":0,"NS":0,"window":2766,"checksum":6218,"urgent":0}}]}
```

Trace all DNS packets received ONLY from Google DNS server '8.8.8.8':

```console
tracee --output json --events net_packet_dns.data.src=8.8.8.8

```

(only **systemd-resolved**, since all the other processes are resolving using local systemd-resolved server `127.0.1.1:53`):

```json
{"timestamp":1696255744257383842,"threadStartTime":1695658999333342370,"processorId":6,"processId":472,"cgroupId":2626,"threadId":472,"parentProcessId":1,"hostProcessId":472,"hostThreadId":472,"hostParentProcessId":1,"userId":976,"mountNamespace":4026532555,"pidNamespace":4026531836,"processName":"systemd-resolve","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2006","eventName":"net_packet_dns","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":131662446,"processEntityId":131662446,"parentEntityId":1975426032,"args":[{"name":"src","type":"const char*","value":"8.8.8.8"},{"name":"dst","type":"const char*","value":"192.168.200.50"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":36031},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":57779,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":1,"NSCount":1,"ARCount":1,"questions":[{"name":"www.zip.net","type":"AAAA","class":"IN"}],"answers":[{"name":"www.zip.net","type":"CNAME","class":"IN","TTL":300,"IP":"","NS":"","CNAME":"amazonas.uol.com.br","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"authorities":[{"name":"uol.com.br","type":"SOA","class":"IN","TTL":600,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"a10-dns-uolcsfe1.host.intranet","RName":"root.uol.com.br","serial":2016052887,"refresh":7200,"retry":3600,"expire":432000,"minimum":900},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"additionals":[{"name":"","type":"OPT","class":"Unknown","TTL":0,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}]}}]}
{"timestamp":1696255744409156387,"threadStartTime":1695658999333342370,"processorId":6,"processId":472,"cgroupId":2626,"threadId":472,"parentProcessId":1,"hostProcessId":472,"hostThreadId":472,"hostParentProcessId":1,"userId":976,"mountNamespace":4026532555,"pidNamespace":4026531836,"processName":"systemd-resolve","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2006","eventName":"net_packet_dns","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":131662446,"processEntityId":131662446,"parentEntityId":1975426032,"args":[{"name":"src","type":"const char*","value":"8.8.8.8"},{"name":"dst","type":"const char*","value":"192.168.200.50"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":52190},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":57212,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":2,"NSCount":0,"ARCount":1,"questions":[{"name":"www.zip.net","type":"A","class":"IN"}],"answers":[{"name":"www.zip.net","type":"CNAME","class":"IN","TTL":300,"IP":"","NS":"","CNAME":"amazonas.uol.com.br","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"amazonas.uol.com.br","type":"A","class":"IN","TTL":60,"IP":"200.147.100.53","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"authorities":[],"additionals":[{"name":"","type":"OPT","class":"Unknown","TTL":0,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}]}}]}
{"timestamp":1696255744420477145,"threadStartTime":1695658999333342370,"processorId":6,"processId":472,"cgroupId":2626,"threadId":472,"parentProcessId":1,"hostProcessId":472,"hostThreadId":472,"hostParentProcessId":1,"userId":976,"mountNamespace":4026532555,"pidNamespace":4026531836,"processName":"systemd-resolve","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2006","eventName":"net_packet_dns","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":131662446,"processEntityId":131662446,"parentEntityId":1975426032,"args":[{"name":"src","type":"const char*","value":"8.8.8.8"},{"name":"dst","type":"const char*","value":"192.168.200.50"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":56275},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":54436,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":0,"NSCount":1,"ARCount":1,"questions":[{"name":"amazonas.uol.com.br","type":"AAAA","class":"IN"}],"answers":[],"authorities":[{"name":"uol.com.br","type":"SOA","class":"IN","TTL":518,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"a10-dns-uolcsfe1.host.intranet","RName":"root.uol.com.br","serial":2016052887,"refresh":7200,"retry":3600,"expire":432000,"minimum":900},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"additionals":[{"name":"","type":"OPT","class":"Unknown","TTL":0,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}]}}]}
{"timestamp":1696255744441387358,"threadStartTime":1695658999333342370,"processorId":6,"processId":472,"cgroupId":2626,"threadId":472,"parentProcessId":1,"hostProcessId":472,"hostThreadId":472,"hostParentProcessId":1,"userId":976,"mountNamespace":4026532555,"pidNamespace":4026531836,"processName":"systemd-resolve","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2006","eventName":"net_packet_dns","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":131662446,"processEntityId":131662446,"parentEntityId":1975426032,"args":[{"name":"src","type":"const char*","value":"8.8.8.8"},{"name":"dst","type":"const char*","value":"192.168.200.50"},{"name":"src_port","type":"u16","value":53},{"name":"dst_port","type":"u16","value":33877},{"name":"proto_dns","type":"trace.ProtoDNS","value":{"ID":20551,"QR":1,"opCode":"query","AA":0,"TC":0,"RD":1,"RA":1,"Z":0,"responseCode":"no error","QDCount":1,"ANCount":48,"NSCount":0,"ARCount":1,"questions":[{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN"}],"answers":[{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"manualdaquimica.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"roteiroceara.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"roteirosincriveis.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"enem.club","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"brpaycard.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"200-147-100-53.static.uol.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minizinhachip.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minnisinhashipi.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minnisinhaship.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minnisinhachipi.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minizinhashipi.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minizinhaship.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minizinhachipi.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minisinhashipi.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minisinhaship.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minisinhachipi.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minisinhachip.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minnisinhashipi.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minnisinhaship.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minnisinhachipi.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minnisinhachip.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minizinhashipi.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minizinhaship.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minizinhachipi.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minisinhashipi.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minisinhaship.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minisinhachipi.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minisinhachip.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"www.minnisinhachip.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"minnisinhachip.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"somostodosum.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"poderjp.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"tvpanico.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"jptvweb.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"jptvdigital.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"jptvd.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"jovempantv.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"tvjovempan.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"panicotv.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"tvpanico.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"jptvweb.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"jptvdigital.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"jptvd.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"jp.tv.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"jovempantv.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"tvjovempan.com.br","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"meunegocio.uol","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""},{"name":"53.100.147.200.in-addr.arpa","type":"PTR","class":"IN","TTL":16493,"IP":"","NS":"","CNAME":"","PTR":"biologianet.com","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}],"authorities":[],"additionals":[{"name":"","type":"OPT","class":"Unknown","TTL":0,"IP":"","NS":"","CNAME":"","PTR":"","TXTs":null,"SOA":{"MName":"","RName":"","serial":0,"refresh":0,"retry":0,"expire":0,"minimum":0},"SRV":{"priority":0,"weight":0,"port":0,"name":""},"MX":{"preference":0,"name":""},"OPT":[],"URI":{"priority":0,"weight":0,"target":""},"TXT":""}]}}]}
```

## Network Based Signatures

It is possible to create Golang (or Rego) signatures for the network events. If you haven't read about how to create signatures, do it [HERE](../../custom/golang.md).

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

