---
title: TRACEE-NET-PACKET-HTTP-REQUEST
section: 1
header: Tracee Event Manual
---

## NAME

**net_packet_http_request** - capture and analyze HTTP request packets

## DESCRIPTION

Triggered for each HTTP request packet that reaches or leaves one of the processes being traced. This event provides detailed information about HTTP requests, including headers, URI paths, methods, and metadata, enabling comprehensive web traffic analysis and security monitoring.

HTTP requests are fundamental to web communications, sent by clients (browsers, applications) to servers to retrieve resources, submit data, or interact with web services. Monitoring these requests provides insights into application behavior, security threats, and network performance.

## EVENT SETS

**network_events**

## DATA FIELDS

**metadata** (*trace.PacketMetadata*)
: Packet metadata containing:
  - Source IP address
  - Destination IP address
  - Source port number
  - Destination port number
  - Protocol number (typically 6 for TCP)
  - Total packet length
  - Network interface name

**proto_http** (*trace.ProtoHTTP*)
: HTTP request information containing:
  - **method** (*string*): HTTP method (GET, POST, PUT, DELETE, etc.)
  - **protocol** (*string*): HTTP protocol version (HTTP/1.1, HTTP/2, etc.)
  - **host** (*string*): Target host from Host header
  - **uri_path** (*string*): Requested URI path
  - **headers** (*map[string]string*): HTTP headers as key-value pairs
  - **content_length** (*uint64*): Length of request body content

## DEPENDENCIES

**Event Dependencies:**

- net_packet_http_base: Base HTTP packet capture event for network packet parsing

## USE CASES

- **Security monitoring**: Detect SQL injection, XSS, and other web attacks

- **API monitoring**: Track API usage patterns and performance

- **Compliance auditing**: Monitor web traffic for regulatory compliance

- **Performance analysis**: Analyze request patterns and response times

- **Threat hunting**: Identify suspicious web requests and communication patterns

## HTTP METHODS

Common HTTP methods captured:

- **GET**: Retrieve data from server
- **POST**: Submit data to server
- **PUT**: Update or create resources
- **DELETE**: Remove resources
- **HEAD**: Retrieve headers only
- **OPTIONS**: Query server capabilities
- **PATCH**: Partial resource updates

## IMPORTANT HEADERS

Key HTTP headers monitored:

- **Host**: Target server hostname
- **User-Agent**: Client application information
- **Accept**: Acceptable response content types
- **Authorization**: Authentication credentials
- **Cookie**: Session and state information
- **Referer**: Source page for the request
- **Content-Type**: Request body content type

## SECURITY CONSIDERATIONS

Monitor for suspicious patterns:

- **SQL injection**: Malicious SQL in parameters
- **XSS attempts**: Script injection in parameters
- **Directory traversal**: Path manipulation attempts
- **Unusual user agents**: Potential automated attacks
- **Authentication bypass**: Suspicious authentication patterns

## PERFORMANCE MONITORING

Track performance indicators:

- **Request frequency**: Unusual traffic spikes
- **Large requests**: Potential DoS attempts
- **Slow requests**: Performance bottlenecks
- **Error patterns**: Failed request analysis

## RELATED EVENTS

- **net_packet_http_response**: HTTP response packet capture
- **net_packet_http**: General HTTP packet capture
- **net_packet_tcp**: TCP packet capture for HTTP traffic
- **security_socket_connect**: Socket connection monitoring