package network_protocols

import (
	"bytes"
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/pkg/processContext"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type DnsQueryData struct {
	query      string `json:"query"`
	queryType  string `json:"queryType"`
	queryClass string `json:"queryclass"`
}

func dnsRequestPrototcolsHandler(buffer *bytes.Buffer, meta EventMeta, ctx processContext.ProcessCtx) (external.Event, PacketMeta) {
	b := buffer
	evt, packet := netPacketProtocolHandler(buffer, meta, ctx)
	appendDnsRequestData(&evt, b)
	return evt, packet
}
func appendDnsRequestData(event *external.Event, buffer *bytes.Buffer) {
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	fmt.Println("dns is ", packet.Layer(layers.LayerTypeDNS))
	dnsLayer := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if dnsLayer == nil {
		fmt.Println("errrorrrr")
		return
	}
	for idx, dnsQuestion := range dnsLayer.Questions {
		var request DnsQueryData
		request.query = dnsQuestion.Type.String()
		request.queryType = string(dnsQuestion.Name)
		request.queryClass = string(dnsQuestion.Class)
		event.Args[idx+1] = external.Argument{
			ArgMeta: external.ArgMeta{"dnsQuestion", "network_protocols.DnsQueryData"},
			Value:   request,
		}
		event.ArgsNum++
	}
}
