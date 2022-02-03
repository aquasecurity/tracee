package network_protocols

import (
	"bytes"
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/processContext"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func dnsRequestPrototcolsHandler(buffer *bytes.Buffer, meta EventMeta, ctx processContext.ProcessCtx, eventName string, bootTime uint64) (external.Event, PacketMeta) {
	evt, packet := netPacketProtocolHandler(buffer, meta, ctx, eventName, bootTime)
	appendDnsRequestArgs(&evt, buffer)
	return evt, packet
}

// parseDnsQuestion parse dns request to DnsQueryData
func parseDnsQuestion(question layers.DNSQuestion) external.DnsQueryData {
	var request external.DnsQueryData
	request.Query = question.Type.String()
	request.QueryType = string(question.Name)
	request.QueryClass = fmt.Sprint("", question.Class)
	return request
}

func parseDnsRequest(questions []layers.DNSQuestion) []external.DnsQueryData {
	requests := make([]external.DnsQueryData, 1, 1)
	for _, dnsQuestion := range questions {
		requests = append(requests, parseDnsQuestion(dnsQuestion))
	}
	return requests
}

// appendDnsRequestArgs parse the given buffer to dns questions and adds it to the event
func appendDnsRequestArgs(event *external.Event, buffer *bytes.Buffer) {
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	dnsLayer := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if dnsLayer == nil {
		return
	}
	requests := parseDnsRequest(dnsLayer.Questions)
	for _, request := range requests {
		event.Args = append(event.Args, external.Argument{
			ArgMeta: external.ArgMeta{"dnsQuestion", "external_network.DnsQueryData"},
			Value:   request,
		})
		event.ArgsNum++
	}
}
