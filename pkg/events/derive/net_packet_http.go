package derive

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

const httpMinLen int = 7 // longest http command is "DELETE "

//
// NetPacketHTTP
//

func NetPacketHTTP() DeriveFunction {
	return deriveSingleEvent(events.NetPacketHTTP, deriveHTTP())
}

func deriveHTTP() deriveArgsFunction {
	return deriveHTTPEvents
}

func deriveHTTPEvents(event trace.Event) ([]interface{}, error) {
	net, http, err := eventToProtoHTTP(&event)
	if err != nil {
		return nil, err
	}
	if http == nil {
		return nil, nil // connection related packets
	}
	if net == nil {
		return nil, parsePacketError()
	}

	return []interface{}{
		net.srcIP,
		net.dstIP,
		net.srcPort,
		net.dstPort,
		http,
	}, nil
}

//
// NetPacketHTTPRequest
//

func NetPacketHTTPRequest() DeriveFunction {
	return deriveSingleEvent(events.NetPacketHTTPRequest, deriveHTTPRequest())
}

func deriveHTTPRequest() deriveArgsFunction {
	return deriveHTTPRequestEvents
}

func deriveHTTPRequestEvents(event trace.Event) ([]interface{}, error) {
	net, http, err := eventToProtoHTTPRequest(&event)
	if err != nil {
		return nil, err
	}
	if http == nil {
		return nil, nil // not a request
	}
	if net == nil {
		return nil, err
	}

	meta := convertNetPairToPktMeta(net)

	return []interface{}{
		*meta,
		http,
	}, nil
}

//
// NetPacketHTTPResponse
//

func NetPacketHTTPResponse() DeriveFunction {
	return deriveSingleEvent(events.NetPacketHTTPResponse, deriveHTTPResponse())
}

func deriveHTTPResponse() deriveArgsFunction {
	return deriveHTTPResponseEvents
}

func deriveHTTPResponseEvents(event trace.Event) ([]interface{}, error) {
	net, http, err := eventToProtoHTTPResponse(&event)
	if err != nil {
		return nil, err
	}
	if http == nil {
		return nil, nil // // not a response
	}
	if net == nil {
		return nil, err
	}

	meta := convertNetPairToPktMeta(net)

	return []interface{}{
		*meta,
		http,
	}, nil
}

func eventToProtoHTTP(event *trace.Event) (*netPair, *trace.ProtoHTTP, error) {
	var httpNetPair netPair

	layer7, err := parseUntilLayer7(event, &httpNetPair)
	if err != nil {
		return nil, nil, err
	}
	if layer7 == nil {
		return nil, nil, nil
	}
	layer7Payload := layer7.Payload()

	if len(layer7Payload) > httpMinLen {
		var httpReq *http.Request
		var httpRes *http.Response
		var protoHttp trace.ProtoHTTP

		reader := bufio.NewReader(bytes.NewReader(layer7Payload))

		// event retval encodes HTTP direction
		if event.ReturnValue&protoHttpRequest == protoHttpRequest {

			httpReq, err = http.ReadRequest(reader)
			if err != nil {
				return nil, nil, err
			}

			copyHTTPReqToProtoHTTP(httpReq, &protoHttp)

		} else if event.ReturnValue&protoHttpResponse == protoHttpResponse {

			httpRes, err = http.ReadResponse(reader, nil)
			if err != nil {
				return nil, nil, err
			}

			copyHTTPResToProtoHTTP(httpRes, &protoHttp)

		} else {
			return &httpNetPair, nil, fmt.Errorf("unspecified direction for HTTP packet")
		}

		return &httpNetPair, &protoHttp, nil
	}

	return &httpNetPair, nil, notProtoPacketError("HTTP")
}

func eventToProtoHTTPRequest(event *trace.Event) (*netPair, *trace.ProtoHTTPRequest, error) {
	var httpNetPair netPair

	layer7, err := parseUntilLayer7(event, &httpNetPair)
	if err != nil {
		return nil, nil, err
	}
	if layer7 == nil {
		return nil, nil, nil
	}
	layer7Payload := layer7.Payload()

	if len(layer7Payload) > httpMinLen {
		// event retval encodes HTTP direction
		if event.ReturnValue&protoHttpRequest != protoHttpRequest {
			return nil, nil, nil
		}

		reader := bufio.NewReader(bytes.NewReader(layer7Payload))

		httpReq, err := http.ReadRequest(reader)
		if err != nil {
			return nil, nil, err
		}

		var httpRequest trace.ProtoHTTPRequest

		copyHTTPReqToProtoHTTPRequest(httpReq, &httpRequest)

		return &httpNetPair, &httpRequest, nil
	}

	return &httpNetPair, nil, notProtoPacketError("HTTP")
}

func eventToProtoHTTPResponse(event *trace.Event) (*netPair, *trace.ProtoHTTPResponse, error) {
	var httpNetPair netPair

	layer7, err := parseUntilLayer7(event, &httpNetPair)
	if err != nil {
		return nil, nil, err
	}
	if layer7 == nil {
		return nil, nil, nil
	}
	layer7Payload := layer7.Payload()

	if len(layer7Payload) > httpMinLen {
		// event retval encodes HTTP direction
		if event.ReturnValue&protoHttpResponse != protoHttpResponse {
			return nil, nil, nil
		}

		reader := bufio.NewReader(bytes.NewReader(layer7Payload))

		httpRes, err := http.ReadResponse(reader, nil)
		if err != nil {
			return nil, nil, err
		}

		var httpResponse trace.ProtoHTTPResponse

		copyHTTPResToProtoHTTPResponse(httpRes, &httpResponse)

		return &httpNetPair, &httpResponse, nil
	}

	return &httpNetPair, nil, notProtoPacketError("HTTP")
}

func copyHTTPReqToProtoHTTP(httpReq *http.Request, proto *trace.ProtoHTTP) {
	proto.Direction = "request"
	proto.Method = httpReq.Method
	proto.Protocol = httpReq.Proto
	proto.Host = httpReq.Host
	proto.URIPath = httpReq.URL.Path
	proto.Headers = httpReq.Header
	proto.ContentLength = httpReq.ContentLength
}

func copyHTTPResToProtoHTTP(httpRes *http.Response, proto *trace.ProtoHTTP) {
	proto.Direction = "response"
	proto.Status = httpRes.Status
	proto.StatusCode = httpRes.StatusCode
	proto.Protocol = httpRes.Proto
	proto.Headers = httpRes.Header
	proto.ContentLength = httpRes.ContentLength
}

func copyHTTPReqToProtoHTTPRequest(httpReq *http.Request, proto *trace.ProtoHTTPRequest) {
	proto.Method = httpReq.Method
	proto.Protocol = httpReq.Proto
	proto.Host = httpReq.Host
	proto.URIPath = httpReq.URL.Path
	proto.Headers = httpReq.Header
	proto.ContentLength = httpReq.ContentLength
}

func copyHTTPResToProtoHTTPResponse(httpRes *http.Response, proto *trace.ProtoHTTPResponse) {
	proto.Status = httpRes.Status
	proto.StatusCode = httpRes.StatusCode
	proto.Protocol = httpRes.Proto
	proto.Headers = httpRes.Header
	proto.ContentLength = httpRes.ContentLength
}
