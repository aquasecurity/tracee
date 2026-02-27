Tracee offers a set of network events that makes it easy to trace network
activity in common protocols.

## Available network events

- [net_packet_ipv4](man/network/net_packet_ipv4.md)
- [net_packet_ipv6](man/network/net_packet_ipv6.md)
- [net_packet_tcp](man/network/net_packet_tcp.md)
- [net_packet_udp](man/network/net_packet_udp.md)
- [net_packet_icmp](man/network/net_packet_icmp.md)
- [net_packet_icmpv6](man/network/net_packet_icmpv6.md)
- [net_packet_dns](man/network/net_packet_dns.md)
- [net_packet_dns_request](man/network/net_packet_dns_request.md)
- [net_packet_dns_response](man/network/net_packet_dns_response.md)
- [net_packet_http](man/network/net_packet_http.md)
- [net_packet_http_request](man/network/net_packet_http_request.md)
- [net_packet_http_response](man/network/net_packet_http_response.md)

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

## Network Based Detectors

It is possible to create Golang detectors for the network events. If you haven't read about how to create detectors, do it [HERE](../custom/golang.md).

!!! Examples Note
    Below is an example of how to create a detector for the `net_packet_dns` event. This same example is used by Tracee CI/CD tests and can be found at the [GitHub repository](https://github.com/aquasecurity/tracee/tree/main/detectors/e2e), together with other e2e detectors for network events.

1. **net_packet_dns** detector example

!!! Note
    For complete detector implementations, see the [detectors/e2e](https://github.com/aquasecurity/tracee/tree/main/detectors/e2e) directory and the [Detector API documentation](../../detectors/api-reference.md).

```golang
package main

import (
    "context"
    "strings"

    "github.com/aquasecurity/tracee/api/v1beta1"
    "github.com/aquasecurity/tracee/api/v1beta1/detection"
)

//
// HOWTO: The way to trigger this test detector is to execute:
//
//        nslookup -type=mx uol.com.br      and then
//        nslookup -type=ns uol.com.br      and then
//        nslookup -type=soa uol.com.br     and then
//        nslookup -type=txt uol.com.br
//
//        This will cause it trigger once and reset its state.

// DNSDetector monitors DNS responses for specific record types
type DNSDetector struct {
    logger    detection.Logger
    foundMX   bool
    foundNS   bool
    foundSOA  bool
    foundTXTs bool
}

func (d *DNSDetector) GetDefinition() detection.DetectorDefinition {
    return detection.DetectorDefinition{
        ID: "DNS",
        Requirements: detection.DetectorRequirements{
            Events: []detection.EventRequirement{
                {
                    Name:       "net_packet_dns",
                    Dependency: detection.DependencyRequired,
                },
            },
        },
        ProducedEvent: v1beta1.EventDefinition{
            Name:        "DNS",
            Description: "Network DNS Detection Example",
            Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
            Tags:        []string{"network", "dns"},
        },
        AutoPopulate: detection.AutoPopulateFields{
            Threat:       true,
            DetectedFrom: true,
        },
    }
}

func (d *DNSDetector) Init(params detection.DetectorParams) error {
    d.logger = params.Logger
    d.foundMX = false
    d.foundNS = false
    d.foundSOA = false
    d.foundTXTs = false
    d.logger.Debugw("DNSDetector initialized")
    return nil
}

func (d *DNSDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    // Extract proto_dns data from event
    var dns *v1beta1.DNS
    for _, data := range event.Data {
        if data.Name == "proto_dns" {
            if v, ok := data.Value.(*v1beta1.EventValue_Dns); ok {
                dns = v.Dns
            }
            break
        }
    }

    if dns == nil || len(dns.Answers) == 0 {
        return nil, nil
    }

    // Check DNS answers for specific record types
    for _, answer := range dns.Answers {
        // Check if MX record exists
        if answer.Mx != nil && answer.Mx.Name == "mx.uol.com.br" && answer.Mx.Preference == 10 {
            d.foundMX = true
            d.logger.Infow("found MX record", "name", answer.Mx.Name)
        }
        // Check if NS record exists
        if answer.Ns == "eliot.uol.com.br" {
            d.foundNS = true
            d.logger.Infow("found NS record", "name", answer.Ns)
        }
        // Check if SOA record exists
        if answer.Soa != nil && answer.Soa.Rname == "root.uol.com.br" {
            d.foundSOA = true
            d.logger.Infow("found SOA record", "rname", answer.Soa.Rname)
        }
        // Check if TXT records exist
        if len(answer.Txts) > 0 {
            for _, txt := range answer.Txts {
                if strings.Contains(txt, "spf.uol.com.br") {
                    d.foundTXTs = true
                    d.logger.Infow("found TXT record", "content", txt)
                }
            }
        }
    }

    // Only trigger detection when all record types are found
    if !d.foundMX || !d.foundNS || !d.foundSOA || !d.foundTXTs {
        return nil, nil
    }

    // Reset state for next detection cycle
    d.foundMX = false
    d.foundNS = false
    d.foundSOA = false
    d.foundTXTs = false

    // Return detection with enriched data
    return detection.Detected(
        detection.WithFields(
            v1beta1.NewStringValue("domain", "uol.com.br"),
            v1beta1.NewStringValue("record_types", "MX,NS,SOA,TXT"),
        ),
    ), nil
}

func (d *DNSDetector) Close() error {
    d.logger.Debugw("DNSDetector closed")
    return nil
}
```

