package network_protocols

import (
	"bytes"
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/pkg/processContext"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func dnsRequestPrototcolsHandler(buffer *bytes.Buffer, meta EventMeta, ctx processContext.ProcessCtx) (external.Event, PacketMeta) {
	evt, packet := netPacketProtocolHandler(buffer, meta, ctx)
	appendDnsRequestData(&evt, buffer)
	return evt, packet
}

// appendDnsRequestData parse the given buffer to dns questions and adds it to the event
func appendDnsRequestData(event *external.Event, buffer *bytes.Buffer) {
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	dnsLayer := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if dnsLayer == nil {
		return
	}
	for _, dnsQuestion := range dnsLayer.Questions {
		var request external.DnsQueryData
		request.Query = dnsQuestion.Type.String()
		request.QueryType = string(dnsQuestion.Name)
		request.QueryClass = fmt.Sprint("", dnsQuestion.Class)
		event.Args = append(event.Args, external.Argument{
			ArgMeta: external.ArgMeta{"dnsQuestion", "network_protocols.DnsQueryData"},
			Value:   request,
		})
		event.ArgsNum++
	}
}
