---
title: TRACEE-NET-PACKET-HTTP
section: 1
header: Tracee Event Manual
---

## NAME

**net_packet_http** - capture HTTP packet traffic

## DESCRIPTION

This event captures HTTP (Hypertext Transfer Protocol) packets in the network traffic. HTTP is the foundation of data communication on the World Wide Web, used for transmitting web pages, APIs, and other web resources. The event provides detailed information about both HTTP requests and responses, including headers, methods, status codes, and metadata.

The event captures both incoming and outgoing HTTP traffic, making it valuable for monitoring web traffic, debugging applications, and detecting security issues.

## EVENT SETS

**network_events**

## DATA FIELDS

**src** (*string*)
: Source IP address

**dst** (*string*)
: Destination IP address

**src_port** (*uint16*)
: Source port number

**dst_port** (*uint16*)
: Destination port number

**metadata** (*trace.PacketMetadata*)
: Additional packet metadata

**proto_http** (*trace.ProtoHTTP*)
: HTTP protocol information containing:
  - **direction** (*string*): "request" or "response"
  - **method** (*string*): HTTP method (GET, POST, etc.)
  - **protocol** (*string*): Protocol version
  - **host** (*string*): Target host
  - **uri_path** (*string*): Request URI path
  - **status** (*string*): Response status text
  - **status_code** (*int*): Response status code
  - **headers** (*map[string][]string*): HTTP headers
  - **content_length** (*int64*): Content length

## DEPENDENCIES

- `net_packet_http_base`: Base HTTP packet processing

## USE CASES

- **Web traffic monitoring**: Track HTTP communications

- **Application debugging**: Diagnose HTTP issues

- **Security analysis**: Detect web-based threats

- **Performance monitoring**: Track response times

## HTTP METHODS

Common HTTP methods:

- **GET**: Retrieve resources
- **POST**: Submit data
- **PUT**: Update resources
- **DELETE**: Remove resources
- **HEAD**: Get headers only
- **OPTIONS**: Get capabilities
- **PATCH**: Partial updates

## REQUEST COMPONENTS

Key request elements:

- **Method**: Action to perform
- **URI**: Resource identifier
- **Headers**: Metadata fields
- **Query parameters**: URL parameters
- **Body**: Request payload
- **Cookies**: Session data

## RESPONSE COMPONENTS

Key response elements:

- **Status code**: Result indicator
- **Headers**: Metadata fields
- **Body**: Response content
- **Content type**: Data format
- **Cookies**: Session updates
- **Cache control**: Caching directives

## SECURITY IMPLICATIONS

Important security aspects:

- **Sensitive data exposure**: Clear text transmission
- **Authentication tokens**: Session management
- **Input validation**: Request parameters
- **Response headers**: Security controls
- **Error messages**: Information disclosure
- **HTTP methods**: Access control

## RELATED EVENTS

- **net_packet_http_request**: HTTP request events
- **net_packet_http_response**: HTTP response events
- **net_packet_tcp**: TCP packet events
- **net_packet_dns**: DNS resolution events
