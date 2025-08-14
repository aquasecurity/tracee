---
title: TRACEE-NET-PACKET-HTTP-RESPONSE
section: 1
header: Tracee Event Manual
---

## NAME

**net_packet_http_response** - capture HTTP response packets

## DESCRIPTION

This event captures HTTP response packets in the network traffic. HTTP responses are server's answers to client requests, containing requested resources along with metadata about the response. The event provides detailed information about response status, headers, and network metadata.

The event is particularly useful for monitoring server responses, debugging web applications, and analyzing web traffic patterns. It captures both successful and error responses, making it valuable for troubleshooting and security monitoring.

## EVENT SETS

**default**, **network_events**

## DATA FIELDS

**metadata** (*trace.PktMeta*)
: Network packet metadata containing:
  - **src_ip** (*string*): Source IP address
  - **dst_ip** (*string*): Destination IP address
  - **src_port** (*uint16*): Source port number
  - **dst_port** (*uint16*): Destination port number
  - **protocol** (*uint8*): IP protocol number
  - **packet_len** (*uint32*): Packet length
  - **iface** (*string*): Network interface

**http_response** (*trace.ProtoHTTPResponse*)
: HTTP response data containing:
  - **status** (*string*): Response status text
  - **status_code** (*int*): Response status code
  - **protocol** (*string*): Protocol version
  - **headers** (*map[string][]string*): Response headers
  - **content_length** (*int64*): Content length

## DEPENDENCIES

- `net_packet_http_base`: Base HTTP packet processing

## USE CASES

- **Response monitoring**: Track server responses

- **Error detection**: Identify failed requests

- **Performance analysis**: Monitor response times

- **Security monitoring**: Detect suspicious responses

## STATUS CODES

Common response codes:

- **2xx Success**: Request fulfilled
  - 200 OK: Standard success
  - 201 Created: Resource created
  - 204 No Content: Success, no body

- **3xx Redirection**: Further action needed
  - 301 Moved Permanently
  - 302 Found
  - 304 Not Modified

- **4xx Client Error**: Client-side issue
  - 400 Bad Request
  - 401 Unauthorized
  - 403 Forbidden
  - 404 Not Found

- **5xx Server Error**: Server-side issue
  - 500 Internal Server Error
  - 502 Bad Gateway
  - 503 Service Unavailable

## RESPONSE HEADERS

Important headers:

- **Content-Type**: Response format
- **Content-Length**: Body size
- **Cache-Control**: Caching directives
- **Set-Cookie**: Session management
- **Location**: Redirect target
- **Server**: Server software
- **Date**: Response timestamp

## SECURITY IMPLICATIONS

Important security aspects:

- **Information disclosure**: Error messages
- **Session management**: Cookie handling
- **Access control**: Auth headers
- **Security headers**: CORS, CSP
- **Server information**: Version leaks
- **Response injection**: XSS, MIME sniffing

## RELATED EVENTS

- **net_packet_http**: General HTTP packets
- **net_packet_http_request**: HTTP request packets
- **net_packet_tcp**: TCP packet events
- **net_packet_dns**: DNS resolution events
