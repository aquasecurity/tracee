# DNS Request Kernel

## DNS Request Kernel

Check [net_packet_dns.md](net_packet_dns.md) for more information on DNS. The
**DNS Request Kernel** event shows DNS queries captured at the kernel level.

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

### dns_request_kernel

The `dns_request_kernel` event provides a **simple, reliable, and efficient**
alternative to network packet-based DNS monitoring. Unlike the complex network
event infrastructure that relies on packet capture and filtering, this event uses
a direct kernel hook on the `udp_sendmsg` function, making it more reliable and
performant.

#### Why Use This Event?

* **Reliability**: Unlike network packet events that depend on complex packet capture infrastructure, this event directly hooks kernel functions, ensuring more consistent and reliable event generation
* **Simplicity**: Uses a straightforward kernel probe approach without the complexity of network packet parsing and filtering
* **Performance**: More efficient than network packet monitoring as it avoids the overhead of packet capture, filtering, and parsing infrastructure
* **Kernel-level accuracy**: Captures DNS requests at the kernel level before they leave the system, providing definitive process attribution

#### Key Features

* **Kernel-level monitoring**: Captures DNS requests at the kernel level by hooking the `udp_sendmsg` function
* **Port-based filtering**: Only captures UDP packets destined for port 53 (DNS)
* **Multiple data formats**: Supports both iovec and ubuf message formats
* **DNS parsing**: Automatically parses DNS messages to extract hostname and query type information
* **Process context**: Provides full process context including process name, PID, and other metadata

#### Advantages

* **Reliability**: Direct kernel hooking provides more consistent event generation compared to network packet capture
* **Performance**: Efficient kernel-level monitoring without network packet processing overhead
* **Simplicity**: Straightforward implementation without complex network infrastructure dependencies
* **Early detection**: Captures DNS requests before they leave the system
* **Process attribution**: Provides clear process context for each DNS request
* **Kernel-level accuracy**: Not affected by network-level filtering or NAT

#### Limitations

* **UDP only**: Only captures UDP-based DNS requests (not TCP DNS)
* **Single iovec node**: Currently supports only the first iovec node in multi-node vectors
* **Kernel version dependency**: Requires specific kernel features for iov_iter handling

## Arguments

* `hostname`:`string` - The domain name being queried (e.g., "google.com")
* `query_type`:`string` - The type of DNS query (e.g., "A", "AAAA", "MX", "TXT")

## Hooks

### udp_sendmsg

#### Type

KProbe

#### Purpose

Hooks the `udp_sendmsg` kernel function to capture UDP packets being sent to port 53. This function is called whenever a process attempts to send a UDP packet, making it an ideal interception point for DNS requests.

The hook performs several key operations:

1. **Port filtering**: Checks if the destination port is 53 (DNS)
2. **Message format detection**: Determines whether the message uses iovec or ubuf format
3. **Data extraction**: Captures the DNS payload from the appropriate message format
4. **Process context**: Records the calling process information

## Example Use Case

Monitoring DNS requests for security analysis:

```console
$ tracee --output json --events dns_request_kernel
```

```json
{
  "timestamp": 1696255905516744399,
  "threadStartTime": 1695658999333342363,
  "processorId": 4,
  "processId": 1234,
  "cgroupId": 2626,
  "threadId": 1234,
  "parentProcessId": 1,
  "hostProcessId": 1234,
  "hostThreadId": 1234,
  "hostParentProcessId": 1,
  "userId": 976,
  "mountNamespace": 4026532555,
  "pidNamespace": 4026531836,
  "processName": "systemd-resolve",
  "executable": {"path": ""},
  "hostName": "example-host",
  "containerId": "",
  "container": {},
  "kubernetes": {},
  "eventId": "2008",
  "eventName": "dns_request_kernel",
  "matchedPolicies": [""],
  "argsNum": 2,
  "returnValue": 0,
  "syscall": "write",
  "stackAddresses": [0],
  "contextFlags": {"containerStarted": false, "isCompat": false},
  "threadEntityId": 131662446,
  "processEntityId": 131662446,
  "parentEntityId": 1975426032,
  "args": [
    {"name": "hostname", "type": "string", "value": "google.com"},
    {"name": "query_type", "type": "string", "value": "A"}
  ]
}
```

This event is particularly useful for:

* **High-performance environments**: When you need efficient DNS monitoring without network packet processing overhead
* **Reliable monitoring**: When you require consistent event generation without dependency on network infrastructure
* **Security monitoring**: Detecting suspicious DNS queries or data exfiltration attempts with guaranteed process attribution
* **Network troubleshooting**: Understanding which processes are making DNS requests with kernel-level accuracy
* **Compliance**: Auditing DNS activity for regulatory requirements with reliable event capture
* **Performance analysis**: Identifying DNS-related performance issues without the overhead of packet capture

## Issues

* **Limited iovec support**: Currently only supports the first iovec node in multi-node vectors
* **Kernel compatibility**: Requires specific kernel features for iov_iter handling
* **UDP-only**: Does not capture TCP-based DNS requests

## Related Events

* `net_packet_dns_request` - Network packet-based DNS request monitoring (more complex, relies on network infrastructure)
* `net_packet_dns_response` - DNS response monitoring (network packet-based)
* `net_packet_dns` - General DNS packet monitoring (network packet-based)

## When to Choose This Event

Choose `dns_request_kernel` when you need:
- **Reliable event generation** without network infrastructure dependencies
- **Better performance** by avoiding packet capture overhead
- **Simpler implementation** with direct kernel hooking
- **Guaranteed process attribution** at the kernel level

Choose network packet events when you need:
- DNS response monitoring (this event only captures requests)
- TCP-based DNS monitoring (this event only captures UDP)
- Network-level packet analysis and filtering 