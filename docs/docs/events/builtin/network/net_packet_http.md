## HTTP

The HTTP header is an integral part of the Hypertext Transfer Protocol (HTTP),
which is the foundation of data communication on the World Wide Web. HTTP
headers are metadata included in both HTTP requests and responses, and they
carry essential information about the nature and handling of the data being
transmitted between a client (such as a web browser) and a web server.

Here's an overview of the HTTP header and its significance:

**Request Headers:**

These headers provide information about the client's request, including details
about the requested resource, preferred content types, and client capabilities.

- **User-Agent:** Specifies the user agent (e.g., web browser or client application) making the request.
- **Host:** Indicates the domain name of the web server.
- **Accept:** Specifies the content types that the client can accept.
- **Authorization:** Used for authentication, typically containing credentials.
- **Cookie:** Contains data associated with the user's session.
- **Referer (or Referrer):** Indicates the URL of the referring web page.

```
GET /path/to/resource HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
```

**Response Headers:**

These headers provide information about the server's response, including
metadata about the resource and how it should be handled.

- **Server:** Identifies the web server software and version.
- **Content-Type:** Specifies the media type (e.g., HTML, JSON) of the response content.
- **Content-Length:** Indicates the size of the response body in bytes.
- **Location:** Used for redirection, providing the URL to which the client should redirect.
- **Cache-Control:** Defines caching directives for the client and intermediaries.
- **Set-Cookie:** Sets cookies in the client's browser to maintain stateful information.

```
HTTP/1.1 200 OK
Date: Mon, 03 Oct 2023 12:34:56 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Content-Length: 12345
```

HTTP is the protocol that powers the web by facilitating the exchange of data
between clients and servers. When a user interacts with a web application or
browses a website, their web browser sends HTTP requests to web servers hosting
the requested resources (e.g., web pages, images, scripts). These requests
include HTTP headers that convey important details about the user's preferences
and requirements.

Upon receiving an HTTP request, the web server processes the request, generates
an HTTP response, and attaches its own set of headers to the response. These
headers contain information about the resource being served, its format, caching
policies, and more. For example, the "Content-Type" header specifies whether the
response is HTML, JSON, or another format, while "Content-Length" indicates the
size of the response data.

HTTP headers also play a crucial role in supporting various web features and
security mechanisms. For instance, "Authorization" headers are used for user
authentication, "Referer" headers help track referral sources, and "Cookie"
headers enable session management.

### net_packet_http

The `net_packet_http` event provides one event for each existing HTTP packet
that reaches or leaves one of the processes being traced (or even "all OS
processes for the default run"). As arguments for this event you will find:
`src`, `dst`, `src_port`, `dst_port`, `metadata` arguments, the full HTTP Header, its
contents and more related information.

Example:

```console
$ tracee --output json --events net_packet_http
```

```json
{"timestamp":1696269931297494423,"threadStartTime":1696269818755096557,"processorId":0,"processId":21,"cgroupId":18465,"threadId":99695,"parentProcessId":7,"hostProcessId":691018,"hostThreadId":1091300,"hostParentProcessId":691004,"userId":0,"mountNamespace":4026532885,"pidNamespace":4026532889,"processName":"inform-164","executable":{"path":""},"hostName":"95e88e281c4b","containerId":"95e88e281c4b47994e0d17ac74b83761fbc3ea570c3f1d4b98b6501ecc00dd84","container":{"id":"95e88e281c4b47994e0d17ac74b83761fbc3ea570c3f1d4b98b6501ecc00dd84"},"kubernetes":{},"eventId":"2009","eventName":"net_packet_http","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"write","stackAddresses":[0],"contextFlags":{"containerStarted":true,"isCompat":false},"threadEntityId":756761678,"processEntityId":1031873185,"parentEntityId":4179927769,"args":[{"name":"src","type":"const char*","value":"172.17.0.2"},{"name":"dst","type":"const char*","value":"192.168.100.11"},{"name":"src_port","type":"u16","value":8080},{"name":"dst_port","type":"u16","value":46348},{"name":"proto_http","type":"trace.ProtoHTTP","value":{"direction":"response","method":"","protocol":"HTTP/1.1","host":"","uri_path":"","status":"200 ","status_code":200,"headers":{"Content-Length":["180"],"Content-Type":["application/x-binary"],"Date":["Mon, 02 Oct 2023 18:05:31 GMT"]},"content_length":180}}]}
{"timestamp":1696269933962085345,"threadStartTime":1696269933920911687,"processorId":6,"processId":1092840,"cgroupId":5650,"threadId":1092840,"parentProcessId":1037836,"hostProcessId":1092840,"hostThreadId":1092840,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"curl","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2009","eventName":"net_packet_http","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"sendto","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":3903007647,"processEntityId":3903007647,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"192.168.200.50"},{"name":"dst","type":"const char*","value":"142.251.128.68"},{"name":"src_port","type":"u16","value":54894},{"name":"dst_port","type":"u16","value":80},{"name":"proto_http","type":"trace.ProtoHTTP","value":{"direction":"request","method":"GET","protocol":"HTTP/1.1","host":"www.google.com","uri_path":"/","status":"","status_code":0,"headers":{"Accept":["*/*"],"User-Agent":["curl/8.3.0"]},"content_length":0}}]}
{"timestamp":1696269934070871329,"threadStartTime":1696269933920911687,"processorId":6,"processId":1092840,"cgroupId":5650,"threadId":1092840,"parentProcessId":1037836,"hostProcessId":1092840,"hostThreadId":1092840,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"curl","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2009","eventName":"net_packet_http","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":3903007647,"processEntityId":3903007647,"parentEntityId":2142180145,"args":[{"name":"src","type":"const char*","value":"142.251.128.68"},{"name":"dst","type":"const char*","value":"192.168.200.50"},{"name":"src_port","type":"u16","value":80},{"name":"dst_port","type":"u16","value":54894},{"name":"proto_http","type":"trace.ProtoHTTP","value":{"direction":"response","method":"","protocol":"HTTP/1.1","host":"","uri_path":"","status":"200 OK","status_code":200,"headers":{"Accept-Ranges":["none"],"Cache-Control":["private, max-age=0"],"Content-Security-Policy-Report-Only":["object-src 'none';base-uri 'self';script-src 'nonce-KaLfx0e0TtSb-jA3800WsQ' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp"],"Content-Type":["text/html; charset=ISO-8859-1"],"Date":["Mon, 02 Oct 2023 18:05:29 GMT"],"Expires":["-1"],"P3p":["CP=\"This is not a P3P policy! See g.co/p3phelp for more info.\""],"Server":["gws"],"Set-Cookie":["1P_JAR=2023-10-02-18; expires=Wed, 01-Nov-2023 18:05:29 GMT; path=/; domain=.google.com; Secure","AEC=Ackid1S2DnK3U6XCf0FULRi0Fa9KOmCQYPGhJZCO_DxYQY2rKyEM5VJ-NDs; expires=Sat, 30-Mar-2024 18:05:29 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax","NID=511=aaaaaaaaaaaA-IoAv6rXsHvxqFmEHiEas5ZKLzivyXGGdxKF5dqeg-UG9J-Bvi5wRGTn5Ti9Iyvi6oDsu3WDKRw7O2ZoeRAOwfNNB40o9wjyBcm0PDBX54oxl4E8NYE4wewzI5K3BzxZi6rLncb__EDzlEcCLEvAQpCB-iIX70o; expires=Tue, 02-Apr-2024 18:05:29 GMT; path=/; domain=.google.com; HttpOnly"],"Vary":["Accept-Encoding"],"X-Frame-Options":["SAMEORIGIN"],"X-Xss-Protection":["0"]},"content_length":-1}}]}
{"timestamp":1696269935497378027,"threadStartTime":1696269818755096557,"processorId":7,"processId":21,"cgroupId":18465,"threadId":99695,"parentProcessId":7,"hostProcessId":691018,"hostThreadId":1091300,"hostParentProcessId":691004,"userId":0,"mountNamespace":4026532885,"pidNamespace":4026532889,"processName":"inform-164","executable":{"path":""},"hostName":"95e88e281c4b","containerId":"95e88e281c4b47994e0d17ac74b83761fbc3ea570c3f1d4b98b6501ecc00dd84","container":{"id":"95e88e281c4b47994e0d17ac74b83761fbc3ea570c3f1d4b98b6501ecc00dd84"},"kubernetes":{},"eventId":"2009","eventName":"net_packet_http","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"write","stackAddresses":[0],"contextFlags":{"containerStarted":true,"isCompat":false},"threadEntityId":756761678,"processEntityId":1031873185,"parentEntityId":4179927769,"args":[{"name":"src","type":"const char*","value":"172.17.0.2"},{"name":"dst","type":"const char*","value":"192.168.100.13"},{"name":"src_port","type":"u16","value":8080},{"name":"dst_port","type":"u16","value":35830},{"name":"proto_http","type":"trace.ProtoHTTP","value":{"direction":"response","method":"","protocol":"HTTP/1.1","host":"","uri_path":"","status":"200 ","status_code":200,"headers":{"Content-Length":["263"],"Content-Type":["application/x-binary"],"Date":["Mon, 02 Oct 2023 18:05:35 GMT"]},"content_length":263}}]}
{"timestamp":1696269935578759155,"threadStartTime":1696269818755096557,"processorId":3,"processId":21,"cgroupId":18465,"threadId":99695,"parentProcessId":7,"hostProcessId":691018,"hostThreadId":1091300,"hostParentProcessId":691004,"userId":0,"mountNamespace":4026532885,"pidNamespace":4026532889,"processName":"inform-164","executable":{"path":""},"hostName":"95e88e281c4b","containerId":"95e88e281c4b47994e0d17ac74b83761fbc3ea570c3f1d4b98b6501ecc00dd84","container":{"id":"95e88e281c4b47994e0d17ac74b83761fbc3ea570c3f1d4b98b6501ecc00dd84"},"kubernetes":{},"eventId":"2009","eventName":"net_packet_http","matchedPolicies":[""],"argsNum":5,"returnValue":0,"syscall":"write","stackAddresses":[0],"contextFlags":{"containerStarted":true,"isCompat":false},"threadEntityId":756761678,"processEntityId":1031873185,"parentEntityId":4179927769,"args":[{"name":"src","type":"const char*","value":"172.17.0.2"},{"name":"dst","type":"const char*","value":"192.168.100.12"},{"name":"src_port","type":"u16","value":8080},{"name":"dst_port","type":"u16","value":51430},{"name":"proto_http","type":"trace.ProtoHTTP","value":{"direction":"response","method":"","protocol":"HTTP/1.1","host":"","uri_path":"","status":"200 ","status_code":200,"headers":{"Content-Length":["319"],"Content-Type":["application/x-binary"],"Date":["Mon, 02 Oct 2023 18:05:35 GMT"]},"content_length":319}}]}
```
