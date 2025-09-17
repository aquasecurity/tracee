# dns_request_kernel(1)

## NAME

dns_request_kernel - Kernel-level DNS request capture event

## DESCRIPTION

The **dns_request_kernel** event shows DNS queries captured at the kernel level. Check [net_packet_dns.md](net_packet_dns.md) for more information on DNS. This event provides a **simple, reliable, and efficient** alternative to network packet-based DNS monitoring. Unlike the complex network event infrastructure that relies on packet capture and filtering, this event uses a direct kernel hook on the `udp_sendmsg` function, making it more reliable and performant.

DNS queries come in various types, each serving a specific purpose in the domain name resolution process or in retrieving information from DNS servers:

- **Standard Query (A or AAAA)**: Requests IPv4 (A) or IPv6 (AAAA) address associated with a given domain name
- **Inverse Query (PTR)**: Provides an IP address and asks for the associated domain name (PTR record)
- **Mail Exchange Query (MX)**: Retrieves mail exchange servers responsible for receiving email for a specific domain
- **Name Server Query (NS)**: Discovers the authoritative name servers for a domain
- **Start of Authority Query (SOA)**: Retrieves SOA record containing essential information about the domain
- **Service Query (SRV)**: Locates services associated with a specific domain (SIP, XMPP, LDAP)
- **Text Query (TXT)**: Retrieves text-based information associated with a domain
- **Canonical Name Query (CNAME)**: Finds the canonical (true) name of an alias domain
- **Pointer Query (PTR) for IPv6**: Similar to PTR queries for IPv4, but for IPv6 addresses
- **Wildcard Query**: Uses '*' character to match multiple subdomains or hostnames within a domain

**Key Features:**
- **Kernel-level monitoring**: Captures DNS requests at the kernel level by hooking the `udp_sendmsg` function
- **Port-based filtering**: Only captures UDP packets destined for port 53 (DNS)
- **Multiple data formats**: Supports both iovec and ubuf message formats
- **DNS parsing**: Automatically parses DNS messages to extract hostname and query type information
- **Process context**: Provides full process context including process name, PID, and other metadata

**Advantages:**
- **Reliability**: Direct kernel hooking provides more consistent event generation compared to network packet capture
- **Performance**: Efficient kernel-level monitoring without network packet processing overhead
- **Simplicity**: Straightforward implementation without complex network infrastructure dependencies
- **Early detection**: Captures DNS requests before they leave the system
- **Process attribution**: Provides clear process context for each DNS request
- **Kernel-level accuracy**: Not affected by network-level filtering or NAT

**Limitations:**
- **UDP only**: Only captures UDP-based DNS requests (not TCP DNS)
- **Single iovec node**: Currently supports only the first iovec node in multi-node vectors
- **Kernel version dependency**: Requires specific kernel features for iov_iter handling

## EVENT SETS

This event is included in the following event sets:

- **network_events**: Network-related events

## DATA FIELDS

**hostname** (*string*)
: The domain name being queried (e.g., "google.com")

**query_type** (*string*)
: The type of DNS query (e.g., "A", "AAAA", "MX", "TXT")

## DEPENDENCIES

**Kernel Hooks:**

- udp_sendmsg: KProbe hook on the `udp_sendmsg` kernel function to capture UDP packets being sent to port 53. This function is called whenever a process attempts to send a UDP packet, making it an ideal interception point for DNS requests.

The hook performs several key operations:
1. **Port filtering**: Checks if the destination port is 53 (DNS)
2. **Message format detection**: Determines whether the message uses iovec or ubuf format
3. **Data extraction**: Captures the DNS payload from the appropriate message format
4. **Process context**: Records the calling process information

## USE CASES

- **High-performance environments**: When you need efficient DNS monitoring without network packet processing overhead

- **Reliable monitoring**: When you require consistent event generation without dependency on network infrastructure

- **Security monitoring**: Detecting suspicious DNS queries or data exfiltration attempts with guaranteed process attribution

- **Network troubleshooting**: Understanding which processes are making DNS requests with kernel-level accuracy

- **Compliance**: Auditing DNS activity for regulatory requirements with reliable event capture

- **Performance analysis**: Identifying DNS-related performance issues without the overhead of packet capture

## RELATED EVENTS

- **net_packet_dns**: General DNS packet events (both requests and responses)

- **net_packet_dns_request**: Network packet-based DNS request monitoring (more complex, relies on network infrastructure)

- **net_packet_dns_response**: DNS response monitoring (network packet-based)

## EXAMPLE

```console
$ tracee --output json --events dns_request_kernel
```

The event captures DNS queries with detailed process context and DNS query information:

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

Choose `dns_request_kernel` when you need reliable event generation without network infrastructure dependencies, better performance by avoiding packet capture overhead, simpler implementation with direct kernel hooking, and guaranteed process attribution at the kernel level.

Choose network packet events when you need DNS response monitoring (this event only captures requests), TCP-based DNS monitoring (this event only captures UDP), or network-level packet analysis and filtering. 