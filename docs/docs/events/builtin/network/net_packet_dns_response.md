## DNS Response

Check [net_packet_dns.md](net_packet_dns.md) for more information on DNS. The
**DNS Response** event shows DNS answers only.

DNS responses come in various types, corresponding to the different types of DNS
queries and the information stored in DNS resource records (RRs).

Here are some common types of DNS responses:

1. **Standard Response (A or AAAA):** This is the most common type of DNS response. It contains the IPv4 (A) or IPv6 (AAAA) address associated with the queried domain name. For example, when you request the IP address of "www.example.com," the DNS response contains the IP address.
2. **Inverse Response (PTR):** Inverse responses provide reverse DNS mapping by associating an IP address with a domain name. This is often used in reverse DNS lookups to translate an IP address into a domain name.
3. **Mail Exchange Response (MX):** MX responses provide information about the mail exchange servers responsible for receiving email for a specific domain. These responses include the priority and FQDN of the mail servers.
4. **Name Server Response (NS):** NS responses specify the authoritative name servers for a domain. These are the servers that hold the DNS records for that domain.
5. **Start of Authority Response (SOA):** SOA responses contain information about the primary name server, contact information, and timing data for DNS updates for a specific domain.
6. **Service Response (SRV):** SRV responses provide information about services associated with a domain. These responses allow clients to discover services like SIP, XMPP, or LDAP and the associated server addresses and ports.
7. **Text Response (TXT):** TXT responses contain text-based information associated with a domain. TXT records are versatile and can include various types of data, such as human-readable text and machine-readable data used for authentication, verification, or policy records.
8. **Canonical Name Response (CNAME):** CNAME responses indicate that the queried domain name is an alias (canonical name) for another domain name. The response provides the canonical (true) name to which the alias points.
9. **Pointer Response (PTR) for IPv4:** PTR responses provide the reverse DNS mapping for IPv4 addresses, associating an IP address with its corresponding domain name.
10. **Pointer Response (PTR) for IPv6:** Similar to IPv4 PTR responses, PTR responses for IPv6 provide the reverse DNS mapping for IPv6 addresses, associating an IPv6 address with its domain name.
11. **Not Found Response (NXDOMAIN):** This response indicates that the queried domain name does not exist in the DNS zone. It is used when there is no matching DNS record for the query.
12. **Wildcard Response:** Wildcard responses are used when a wildcard query matches multiple subdomains or hostnames within a domain. The response provides information for all matching subdomains or hostnames.

These are some of the common types of DNS responses, each serving a specific
purpose in providing DNS information to clients and resolvers. DNS responses are
essential for translating domain names into IP addresses and facilitating
communication on the Internet.

### net_packet_dns_response

The `net_packet_dns_response` provides one event for each existing DNS packet,
containing a query, that reaches or leaves one of the processes being traced (or
even "all OS processes for the default run"). As arguments for this event you
will find: `src`, `dst`, `src_port`, `dst_port` arguments and customized
arguments showing important data about the obtained response.

Example:

```console
$ tracee --output json --events net_packet_dns_response
```

```json
{"timestamp":1696257538821986017,"threadStartTime":1695658999333342058,"processorId":6,"processId":472,"cgroupId":2626,"threadId":472,"parentProcessId":1,"hostProcessId":472,"hostThreadId":472,"hostParentProcessId":1,"userId":976,"mountNamespace":4026532555,"pidNamespace":4026531836,"processName":"systemd-resolve","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2008","eventName":"net_packet_dns_response","matchedPolicies":[""],"argsNum":2,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":131662446,"processEntityId":131662446,"parentEntityId":1975426032,"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"1.1.1.1","dst_ip":"192.168.200.50","src_port":53,"dst_port":34184,"protocol":17,"packet_len":117,"iface":"any"}},{"name":"dns_response","type":"[]trace.DnsResponseData","value":[{"query_data":{"query":"www.zip.net","query_type":"A","query_class":"IN"},"dns_answer":[{"answer_type":"CNAME","ttl":300,"answer":"amazonas.uol.com.br"},{"answer_type":"A","ttl":60,"answer":"200.147.100.53"}]}]}]}
{"timestamp":1696257538822455864,"threadStartTime":1695658999333342058,"processorId":6,"processId":472,"cgroupId":2626,"threadId":472,"parentProcessId":1,"hostProcessId":472,"hostThreadId":472,"hostParentProcessId":1,"userId":976,"mountNamespace":4026532555,"pidNamespace":4026531836,"processName":"systemd-resolve","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2008","eventName":"net_packet_dns_response","matchedPolicies":[""],"argsNum":2,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":131662446,"processEntityId":131662446,"parentEntityId":1975426032,"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"8.8.8.8","dst_ip":"192.168.200.50","src_port":53,"dst_port":55287,"protocol":17,"packet_len":172,"iface":"any"}},{"name":"dns_response","type":"[]trace.DnsResponseData","value":[{"query_data":{"query":"www.zip.net","query_type":"AAAA","query_class":"IN"},"dns_answer":[{"answer_type":"CNAME","ttl":300,"answer":"amazonas.uol.com.br"}]}]}]}
{"timestamp":1696257538823870518,"threadStartTime":1695658999333342058,"processorId":6,"processId":472,"cgroupId":2626,"threadId":472,"parentProcessId":1,"hostProcessId":472,"hostThreadId":472,"hostParentProcessId":1,"userId":976,"mountNamespace":4026532555,"pidNamespace":4026531836,"processName":"systemd-resolve","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2008","eventName":"net_packet_dns_response","matchedPolicies":[""],"argsNum":2,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":131662446,"processEntityId":131662446,"parentEntityId":1975426032,"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"8.8.8.8","dst_ip":"192.168.200.50","src_port":53,"dst_port":42873,"protocol":17,"packet_len":117,"iface":"any"}},{"name":"dns_response","type":"[]trace.DnsResponseData","value":[{"query_data":{"query":"www.zip.net","query_type":"A","query_class":"IN"},"dns_answer":[{"answer_type":"CNAME","ttl":300,"answer":"amazonas.uol.com.br"},{"answer_type":"A","ttl":60,"answer":"200.147.3.199"}]}]}]}
```
