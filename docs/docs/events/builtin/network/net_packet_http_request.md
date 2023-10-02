## HTTP

Check [net_packet_http.md](net_packet_http.md) for more information on HTTP. The
**HTTP Request** event shows HTTP requests only.

HTTP (Hypertext Transfer Protocol) requests are an integral part of how web
browsers and other clients communicate with web servers to retrieve and interact
with web resources. An HTTP request is a message sent by a client (e.g., a web
browser) to a server (e.g., a web server) to request a specific resource, such
as a web page, image, or API endpoint. These requests are fundamental to the
functioning of the World Wide Web and are responsible for loading web pages,
submitting forms, and interacting with web services.

An HTTP request typically includes several key components. Example:

```
GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Referer: https://www.google.com/
Cookie: session_id=1234567890; user_prefs=dark_mode
Connection: keep-alive
```

In this example:

1. **Request Method:** The request uses the `GET` method, indicating a request to retrieve data.
2. **URI:** The URI specifies the resource being requested as `/index.html`. It includes the path to the file on the server.
3. **HTTP Version:** The request uses HTTP/1.1.
4. **Host Header:** The `Host` header indicates the domain name of the server, which is `www.example.com`.
5. **User-Agent Header:** The `User-Agent` header provides information about the client's user agent, which is a web browser (Google Chrome).
6. **Accept Header:** The `Accept` header specifies the types of content the client can accept, including HTML and XML.
7. **Accept-Language Header:** The `Accept-Language` header indicates the preferred languages for content, with English as the primary language.
8. **Referer Header:** The `Referer` header identifies the URL of the referring web page, in this case, Google's search results page.
9. **Cookie Header:** The `Cookie` header includes session information and user preferences as cookies.
10. **Connection Header:** The `Connection` header is set to `keep-alive`, indicating that the client wants to keep the TCP connection open for potential future requests.
11. **...**

> This example represents a simplified HTTP request, but real-world requests can include many more headers and a request body, depending on the specific use case and the web application's requirements. The server processes this request and responds with the appropriate resource, typically in an HTTP response message.

Once the HTTP request is constructed, the client sends it to the server, which
processes the request and generates an HTTP response. The response typically
includes the requested resource, along with its own set of HTTP headers.

HTTP requests are versatile and support various features, including
authentication, caching, content negotiation, and more. They are the foundation
of the web's interactivity and enable users to browse websites, submit forms,
and interact with web applications seamlessly. Developers and webmasters use
HTTP requests extensively when building and maintaining web-based systems to
deliver content and services to users worldwide.

### net_packet_http_request

The `net_packet_http_request` event provides one event for each existing HTTP
request that reaches or leaves one of the processes being traced (or even "all
OS processes for the default run"). As arguments for this event you will find:
`src`, `dst`, `src_port`, `dst_port` arguments, the full HTTP Header, its
contents and more related information.

Example:

```console
$ tracee --output json --events net_packet_http_request
```

```json
{"timestamp":1696259155542061071,"threadStartTime":1696259155505431448,"processorId":6,"processId":1055252,"cgroupId":5650,"threadId":1055252,"parentProcessId":1037836,"hostProcessId":1055252,"hostThreadId":1055252,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"curl","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2010","eventName":"net_packet_http_request","matchedPolicies":[""],"argsNum":2,"returnValue":0,"syscall":"sendto","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":3061510256,"processEntityId":3061510256,"parentEntityId":2142180145,"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"192.168.200.50","dst_ip":"142.251.129.36","src_port":50064,"dst_port":80,"protocol":6,"packet_len":129,"iface":"any"}},{"name":"http_request","type":"trace.ProtoHTTPRequest","value":{"method":"GET","protocol":"HTTP/1.1","host":"www.google.com","uri_path":"/","headers":{"Accept":["*/*"],"User-Agent":["curl/8.3.0"]},"content_length":0}}]}
{"timestamp":1696259158887036266,"threadStartTime":1696203826511069764,"processorId":7,"processId":963213,"cgroupId":5650,"threadId":963219,"parentProcessId":963208,"hostProcessId":963213,"hostThreadId":963219,"hostParentProcessId":963168,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"Chrome_ChildIOT","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2010","eventName":"net_packet_http_request","matchedPolicies":[""],"argsNum":2,"returnValue":0,"syscall":"sendto","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2469898314,"processEntityId":1872563844,"parentEntityId":2821133720,"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"::1","dst_ip":"::1","src_port":49622,"dst_port":8000,"protocol":6,"packet_len":781,"iface":"any"}},{"name":"http_request","type":"trace.ProtoHTTPRequest","value":{"method":"GET","protocol":"HTTP/1.1","host":"localhost:8000","uri_path":"/livereload/600097443/600104814","headers":{"Accept":["*/*"],"Accept-Encoding":["gzip, deflate, br"],"Accept-Language":["en-US,en;q=0.9,pt-BR;q=0.8,pt;q=0.7"],"Connection":["keep-alive"],"Cookie":["org.cups.sid=12344c3a4fd11efabe2dba9519517966; unifises=monAplOcbPmRSi26LDgZiM7fZr31Xwuu; csrf_token=B86NGyz9RgNbLahz6tjrY4qrKdC4try5"],"Dnt":["1"],"Referer":["http://localhost:8000/tracee/docs/events/builtin/network/net_packet_ipv4/"],"Sec-Ch-Ua":["\"Google Chrome\";v=\"117\", \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"117\""],"Sec-Ch-Ua-Mobile":["?0"],"Sec-Ch-Ua-Platform":["\"Linux\""],"Sec-Fetch-Dest":["empty"],"Sec-Fetch-Mode":["cors"],"Sec-Fetch-Site":["same-origin"],"User-Agent":["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"]},"content_length":0}}]}
{"timestamp":1696259158887212058,"threadStartTime":1696255132899010481,"processorId":3,"processId":1022747,"cgroupId":5142,"threadId":1035048,"parentProcessId":1022554,"hostProcessId":1022747,"hostThreadId":1035048,"hostParentProcessId":1302,"userId":0,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"docker-proxy","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2010","eventName":"net_packet_http_request","matchedPolicies":[""],"argsNum":2,"returnValue":0,"syscall":"socket","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":2934239730,"processEntityId":3554267035,"parentEntityId":3216747323,"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"172.17.0.1","dst_ip":"172.17.0.3","src_port":53870,"dst_port":8000,"protocol":6,"packet_len":801,"iface":"any"}},{"name":"http_request","type":"trace.ProtoHTTPRequest","value":{"method":"GET","protocol":"HTTP/1.1","host":"localhost:8000","uri_path":"/livereload/600097443/600104814","headers":{"Accept":["*/*"],"Accept-Encoding":["gzip, deflate, br"],"Accept-Language":["en-US,en;q=0.9,pt-BR;q=0.8,pt;q=0.7"],"Connection":["keep-alive"],"Cookie":["org.cups.sid=12344c3a4ed12efabe2dba9519517966; unifises=monAplOcbPmRSi26LDgZiM7fZr31Xwuu; csrf_token=B86NGyz9RgNbLahz6tjrY4qrKdC4try5"],"Dnt":["1"],"Referer":["http://localhost:8000/tracee/docs/events/builtin/network/net_packet_ipv4/"],"Sec-Ch-Ua":["\"Google Chrome\";v=\"117\", \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"117\""],"Sec-Ch-Ua-Mobile":["?0"],"Sec-Ch-Ua-Platform":["\"Linux\""],"Sec-Fetch-Dest":["empty"],"Sec-Fetch-Mode":["cors"],"Sec-Fetch-Site":["same-origin"],"User-Agent":["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"]},"content_length":0}}]}
{"timestamp":1696259161872205237,"threadStartTime":1696259161583361191,"processorId":0,"processId":1055283,"cgroupId":5650,"threadId":1055283,"parentProcessId":1037836,"hostProcessId":1055283,"hostThreadId":1055283,"hostParentProcessId":1037836,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"curl","executable":{"path":""},"hostName":"rugged","containerId":"","container":{},"kubernetes":{},"eventId":"2010","eventName":"net_packet_http_request","matchedPolicies":[""],"argsNum":2,"returnValue":0,"syscall":"sendto","stackAddresses":[0],"contextFlags":{"containerStarted":false,"isCompat":false},"threadEntityId":4056179853,"processEntityId":4056179853,"parentEntityId":2142180145,"args":[{"name":"metadata","type":"trace.PktMeta","value":{"src_ip":"192.168.200.50","dst_ip":"95.217.163.246","src_port":53810,"dst_port":80,"protocol":6,"packet_len":132,"iface":"any"}},{"name":"http_request","type":"trace.ProtoHTTPRequest","value":{"method":"GET","protocol":"HTTP/1.1","host":"www.archlinux.org","uri_path":"/","headers":{"Accept":["*/*"],"User-Agent":["curl/8.3.0"]},"content_length":0}}]}
```
