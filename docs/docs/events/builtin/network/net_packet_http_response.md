## HTTP Response

HTTP responses are critical components of web communication, providing servers'
answers to clients' requests in the Hypertext Transfer Protocol (HTTP). These
responses contain the requested resources, such as web pages, images, or data,
along with vital metadata. Understanding HTTP responses is essential for web
developers and administrators as they play a pivotal role in delivering web
content to users.

An HTTP response comprises several key components:

```
HTTP/1.1 200 OK
Date: Mon, 03 Oct 2023 12:34:56 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Content-Length: 12345
Cache-Control: max-age=3600, public
Set-Cookie: session_id=abcdef123456; Path=/; Secure; HttpOnly; SameSite=Lax
Last-Modified: Fri, 01 Oct 2023 18:00:00 GMT
ETag: "123456789"
Accept-Ranges: bytes
Connection: keep-alive

<!DOCTYPE html>
<html>
<head>
    <title>Example Page</title>
</head>
<body>
    <h1>Welcome to the Example Page</h1>
    <p>This is a sample HTTP response.</p>
</body>
</html>
```

In this example:

1. **Status Line:** The status line indicates that this is an HTTP/1.1 response with a status code of `200 OK`, indicating a successful response.
2. **Date Header:** The `Date` header specifies the date and time when the response was generated.
3. **Server Header:** The `Server` header identifies the web server software and version running on the server.
4. **Content-Type Header:** The `Content-Type` header indicates that the response contains HTML (`text/html`) with UTF-8 character encoding.
5. **Content-Length Header:** The `Content-Length` header specifies the size of the response body in bytes (12345 bytes).
6. **Cache-Control Header:** The `Cache-Control` header defines caching directives for the client and intermediaries, setting a maximum age of 3600 seconds (1 hour) and allowing public caching.
7. **Set-Cookie Header:** The `Set-Cookie` header sets a session cookie named `session_id` with a secure attribute, HTTP-only attribute, and a SameSite policy of Lax.
8. **Last-Modified Header:** The `Last-Modified` header indicates the date and time when the resource was last modified.
9. **ETag Header:** The `ETag` header provides an entity tag for caching purposes.
10. **Accept-Ranges Header:** The `Accept-Ranges` header indicates that the server supports byte-range requests.
11. **Connection Header:** The `Connection` header is set to `keep-alive`, indicating that the server wants to keep the TCP connection open for potential future requests.
12. **Response Body:** The response body contains an HTML document with a title, heading, and paragraph, which is the actual content of the requested resource.

> This example demonstrates a simplified HTTP response, but real-world responses can contain more headers and a larger response body, depending on the specific resource and server configuration. HTTP responses enable clients to receive and interpret web content, allowing users to view web pages, images, or other resources in their web browsers.

HTTP responses are versatile and can convey various information. They can also
include cookies for session management, set caching policies to optimize
performance, and provide instructions for further actions, such as redirection.

HTTP responses are integral to web browsing and application development,
enabling clients to access and display web content seamlessly. Understanding the
information conveyed within HTTP responses is crucial for developers and
administrators to ensure efficient and secure communication between clients and
servers on the World Wide Web.

### net_packet_http_response

The `net_packet_http_response` event provides one event for each existing HTTP
response that reaches or leaves one of the processes being traced (or even "all
OS processes for the default run"). As arguments for this event you will find:
`src`, `dst`, `src_port`, `dst_port` arguments, the full HTTP Header, its
contents and more related information.

Example:

```console
$ tracee --output json --events net_packet_http_response
```

```json
{"timestamp":1696269878969198725,"threadStartTime":1696268045240158340,"processorId":6,"processId":21,"cgroupId":18465,"threadId":98926,"parentProcessId":7,"hostProcessId":691018,"hostThreadId":1077380,"hostParentProcessId":691004,"userId":0,"mountNamespace":4026532885,"pidNamespace":4026532889,"processName":"inform-161","executable":{"path":""},"hostName":"95e88e281c4b","containerId":"95e88e281c4b47994e0d17ac74b83761fbc3ea570c3f1d4b98b6501ecc00dd84","container":{"id":"95e88e281c4b47994e0d17ac74b83761fbc3ea570c3f1d4b98b6501ecc00dd84"},"kubernetes":{},"eventId":"2011","eventName":"net_packet_http_response","matchedPolicies":[""],"argsNum":2,"returnValue":0,"syscall":"write","stackAddresses":[0],"contextFlags":{"containerStarted":true,"isCompat":false},"threadEntityId":1303867201,"processEntityId":1031873185,"parentEntityId":4179927769,"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"172.17.0.2","dst_ip":"192.168.100.16","src_port":8080,"dst_port":50322,"protocol":6,"packet_len":331,"iface":"any"}},{"name":"http_response","type":"trace.ProtoHTTPResponse","value":{"status":"200 ","status_code":200,"protocol":"HTTP/1.1","headers":{"Content-Length":["180"],"Content-Type":["application/x-binary"],"Date":["Mon, 02 Oct 2023 18:04:38 GMT"]},"content_length":180}}]}
{"timestamp":1696269880377378962,"threadStartTime":1696269880249502196,"processorId":6,"processId":1092254,"cgroupId":5650,"threadId":1092254,"parentProcessId":1037836,"hostProcessId":1092254,"hostThreadId":1092254,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"curl","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2011","eventName":"net_packet_http_response","matchedPolicies":[""],"argsNum":2,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":1225483232,"processEntityId":1225483232,"parentEntityId":2142180145,"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"142.251.132.36","dst_ip":"192.168.200.50","src_port":80,"dst_port":42606,"protocol":6,"packet_len":2852,"iface":"any"}},{"name":"http_response","type":"trace.ProtoHTTPResponse","value":{"status":"200 OK","status_code":200,"protocol":"HTTP/1.1","headers":{"Accept-Ranges":["none"],"Cache-Control":["private, max-age=0"],"Content-Security-Policy-Report-Only":["object-src 'none';base-uri 'self';script-src 'nonce-u5D68fG7x3C4aNvFt9Pg1g' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp"],"Content-Type":["text/html; charset=ISO-8859-1"],"Date":["Mon, 02 Oct 2023 18:04:36 GMT"],"Expires":["-1"],"P3p":["CP=\"This is not a P3P policy! See g.co/p3phelp for more info.\""],"Server":["gws"],"Set-Cookie":["1P_JAR=2023-10-02-18; expires=Wed, 01-Nov-2023 18:04:36 GMT; path=/; domain=.google.com; Secure","AEC=Ackid1R0wdgXEgtb4J6PdiRAgKV9sweuRHnFVEJQpH1gfj0f8yBOtiKokV8; expires=Sat, 30-Mar-2024 18:04:36 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax","NID=511=fhw31kVbscPFimDzfMPJ1r2kduV6AqtzgKUxqZbXwZCMSL3pEFOuqNZCwz3Q6Xwxyv4kRva7uzeF8zu--4PXyIi59PGTmzlMGqqPH_TRuvKq83ktYDkaX-oq3AltqZHGEMwxIzEQZkPhr83glWmlYQKdWFGu39MULyEttMbRLGw; expires=Tue, 02-Apr-2024 18:04:36 GMT; path=/; domain=.google.com; HttpOnly"],"Vary":["Accept-Encoding"],"X-Frame-Options":["SAMEORIGIN"],"X-Xss-Protection":["0"]},"content_length":-1}}]}
{"timestamp":1696269880812078239,"threadStartTime":1696268045240158340,"processorId":6,"processId":21,"cgroupId":18465,"threadId":98926,"parentProcessId":7,"hostProcessId":691018,"hostThreadId":1077380,"hostParentProcessId":691004,"userId":0,"mountNamespace":4026532885,"pidNamespace":4026532889,"processName":"inform-161","executable":{"path":""},"hostName":"95e88e281c4b","containerId":"95e88e281c4b47994e0d17ac74b83761fbc3ea570c3f1d4b98b6501ecc00dd84","container":{"id":"95e88e281c4b47994e0d17ac74b83761fbc3ea570c3f1d4b98b6501ecc00dd84"},"kubernetes":{},"eventId":"2011","eventName":"net_packet_http_response","matchedPolicies":[""],"argsNum":2,"returnValue":0,"syscall":"write","stackAddresses":[0],"contextFlags":{"containerStarted":true,"isCompat":false},"threadEntityId":1303867201,"processEntityId":1031873185,"parentEntityId":4179927769,"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"172.17.0.2","dst_ip":"192.168.100.12","src_port":8080,"dst_port":51420,"protocol":6,"packet_len":260,"iface":"any"}},{"name":"http_response","type":"trace.ProtoHTTPResponse","value":{"status":"200 ","status_code":200,"protocol":"HTTP/1.1","headers":{"Content-Length":["109"],"Content-Type":["application/x-binary"],"Date":["Mon, 02 Oct 2023 18:04:40 GMT"]},"content_length":109}}]}
{"timestamp":1696269882656565968,"threadStartTime":1696268045240158340,"processorId":6,"processId":21,"cgroupId":18465,"threadId":98926,"parentProcessId":7,"hostProcessId":691018,"hostThreadId":1077380,"hostParentProcessId":691004,"userId":0,"mountNamespace":4026532885,"pidNamespace":4026532889,"processName":"inform-161","executable":{"path":""},"hostName":"95e88e281c4b","containerId":"95e88e281c4b47994e0d17ac74b83761fbc3ea570c3f1d4b98b6501ecc00dd84","container":{"id":"95e88e281c4b47994e0d17ac74b83761fbc3ea570c3f1d4b98b6501ecc00dd84"},"kubernetes":{},"eventId":"2011","eventName":"net_packet_http_response","matchedPolicies":[""],"argsNum":2,"returnValue":0,"syscall":"write","stackAddresses":[0],"contextFlags":{"containerStarted":true,"isCompat":false},"threadEntityId":1303867201,"processEntityId":1031873185,"parentEntityId":4179927769,"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"172.17.0.2","dst_ip":"192.168.100.15","src_port":8080,"dst_port":58612,"protocol":6,"packet_len":358,"iface":"any"}},{"name":"http_response","type":"trace.ProtoHTTPResponse","value":{"status":"200 ","status_code":200,"protocol":"HTTP/1.1","headers":{"Content-Length":["207"],"Content-Type":["application/x-binary"],"Date":["Mon, 02 Oct 2023 18:04:42 GMT"]},"content_length":207}}]}
```
