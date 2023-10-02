## DNS Request

Check [net_packet_dns.md](net_packet_dns.md) for more information on DNS. The
**DNS Request** event shows DNS queries only.

DNS queries come in various types, each serving a specific purpose in the domain
name resolution process or in retrieving information from DNS servers.

Here are some common types of DNS queries:

1. **Standard Query (A or AAAA):** This is the most basic type of DNS query. It requests the IPv4 (A) or IPv6 (AAAA) address associated with a given domain name. For example, when you enter a domain like "www.example.com" in your web browser, it sends a standard A or AAAA query to resolve the IP address of the web server.
2. **Inverse Query (PTR):** Inverse queries do the reverse of standard queries. Instead of providing a domain name and asking for an IP address, an inverse query provides an IP address and asks for the associated domain name (PTR record). PTR records are commonly used in reverse DNS lookups to map IP addresses to domain names.
3. **Mail Exchange Query (MX):** MX queries are used to retrieve the mail exchange servers responsible for receiving email for a specific domain. These records specify the mail servers' priority and fully qualified domain names (FQDNs).
4. **Name Server Query (NS):** An NS query is used to discover the authoritative name servers for a domain. These are the servers that hold the DNS records for that domain.
5. **Start of Authority Query (SOA):** SOA queries retrieve the Start of Authority record for a domain. The SOA record contains essential information about the domain, such as the primary name server, contact information, and timing data for DNS updates.
6. **Service Query (SRV):** SRV queries are used to locate services associated with a specific domain. These queries allow for the discovery of services like SIP, XMPP, or LDAP.
7. **Text Query (TXT):** TXT queries retrieve text-based information associated with a domain. TXT records are versatile and can contain various types of data, including human-readable text and machine-readable data used for authentication and verification.
8. **Canonical Name Query (CNAME):** CNAME queries are used to find the canonical (true) name of an alias domain. For example, they allow you to determine the actual domain pointed to by a CNAME record.
9. **Pointer Query (PTR) for IPv6:** While PTR queries are commonly associated with reverse DNS lookups for IPv4 addresses, similar queries can be performed for IPv6 addresses to retrieve the reverse DNS mapping of IPv6 addresses to domain names.
10. **Wildcard Query:** Wildcard queries use the '*' character as a wildcard to match multiple subdomains or hostnames within a domain. They are used to retrieve multiple DNS records that share a common pattern.

These are some of the common DNS query types, each designed to serve a specific
purpose in the DNS resolution process or in retrieving specific DNS information.
DNS queries are an integral part of how the Internet functions, allowing users
and applications to resolve domain names into IP addresses and access services
and resources on the web.

### net_packet_dns_request

The `net_packet_dns_request` provides one event for each existing DNS packet,
containing a query, that reaches or leaves one of the processes being traced (or
even "all OS processes for the default run"). As arguments for this event you
will find: `src`, `dst`, `src_port`, `dst_port` arguments and customized
arguments showing important data about the query being made.

Example:

```console
$ tracee --output json --events net_packet_dns_request
```

```json
{"timestamp":1696255905516744399,"threadStartTime":1695658999333342363,"processorId":4,"processId":472,"cgroupId":2626,"threadId":472,"parentProcessId":1,"hostProcessId":472,"hostThreadId":472,"hostParentProcessId":1,"userId":976,"mountNamespace":4026532555,"pidNamespace":4026531836,"processName":"systemd-resolve","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2007","eventName":"net_packet_dns_request","matchedPolicies":[""],"argsNum":2,"returnValue":0,"syscall":"write","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":131662446,"processEntityId":131662446,"parentEntityId":1975426032,"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"192.168.200.50","dst_ip":"8.8.8.8","src_port":56650,"dst_port":53,"protocol":17,"packet_len":68,"iface":"any"}},{"name":"dns_questions","type":"[]trace.DnsQueryData","value":[{"query":"www.zip.net","query_type":"AAAA","query_class":"IN"}]}]}
{"timestamp":1696255905516817908,"threadStartTime":1695658999333342363,"processorId":4,"processId":472,"cgroupId":2626,"threadId":472,"parentProcessId":1,"hostProcessId":472,"hostThreadId":472,"hostParentProcessId":1,"userId":976,"mountNamespace":4026532555,"pidNamespace":4026531836,"processName":"systemd-resolve","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2007","eventName":"net_packet_dns_request","matchedPolicies":[""],"argsNum":2,"returnValue":0,"syscall":"write","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":131662446,"processEntityId":131662446,"parentEntityId":1975426032,"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"192.168.200.50","dst_ip":"8.8.8.8","src_port":46530,"dst_port":53,"protocol":17,"packet_len":68,"iface":"any"}},{"name":"dns_questions","type":"[]trace.DnsQueryData","value":[{"query":"www.zip.net","query_type":"A","query_class":"IN"}]}]}
{"timestamp":1696255905516899291,"threadStartTime":1695658999333342363,"processorId":4,"processId":472,"cgroupId":2626,"threadId":472,"parentProcessId":1,"hostProcessId":472,"hostThreadId":472,"hostParentProcessId":1,"userId":976,"mountNamespace":4026532555,"pidNamespace":4026531836,"processName":"systemd-resolve","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2007","eventName":"net_packet_dns_request","matchedPolicies":[""],"argsNum":2,"returnValue":0,"syscall":"write","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":131662446,"processEntityId":131662446,"parentEntityId":1975426032,"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"192.168.200.50","dst_ip":"1.1.1.1","src_port":36605,"dst_port":53,"protocol":17,"packet_len":68,"iface":"any"}},{"name":"dns_questions","type":"[]trace.DnsQueryData","value":[{"query":"www.zip.net","query_type":"A","query_class":"IN"}]}]}
```
