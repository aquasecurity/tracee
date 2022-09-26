package derive

import (
	"fmt"
	"net"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NetPacketDNS() deriveFunction {
	return deriveSingleEvent(events.NetPacketDNS, deriveNetPacketDNS())
}

func deriveNetPacketDNS() deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		var ok bool
		var payload []byte
		var layerType gopacket.LayerType
		var srcIP net.IP
		var dstIP net.IP
		var srcPort uint16
		var dstPort uint16

		// sanity checks

		payloadArg := events.GetArg(&event, "payload")
		if payloadArg == nil {
			return nil, fmt.Errorf("no payload ?")
		}
		if payload, ok = payloadArg.Value.([]byte); !ok {
			return nil, fmt.Errorf("non []byte argument ?")
		}
		payloadSize := len(payload)
		if payloadSize < 1 {
			return nil, fmt.Errorf("empty payload ?")
		}

		// initial header type

		switch event.ReturnValue { // event retval tells layer type
		case 2:
			layerType = layers.LayerTypeIPv4
		case 10:
			layerType = layers.LayerTypeIPv6
		default:
			return nil, nil
		}

		// parse packet

		packet := gopacket.NewPacket(
			payload[4:payloadSize],
			layerType,
			gopacket.Default,
		)
		if packet == nil {
			return []interface{}{}, fmt.Errorf("could not parse the packet")
		}

		layer3 := packet.NetworkLayer()

		switch v := layer3.(type) {
		case (*layers.IPv4):
			srcIP = v.SrcIP
			dstIP = v.DstIP
		case (*layers.IPv6):
			srcIP = v.SrcIP
			dstIP = v.DstIP
		default:
			return nil, nil
		}

		layer4 := packet.TransportLayer()

		switch v := layer4.(type) {
		case (*layers.TCP):
			srcPort = uint16(v.SrcPort)
			dstPort = uint16(v.DstPort)
		case (*layers.UDP):
			srcPort = uint16(v.SrcPort)
			dstPort = uint16(v.DstPort)
		default:
			return nil, nil
		}

		layer7 := packet.ApplicationLayer()

		switch l7 := layer7.(type) {
		case (*layers.DNS):
			var dns trace.ProtoDNS
			copyDNSToProtoDNS(l7, &dns)

			return []interface{}{
				srcIP,
				dstIP,
				srcPort,
				dstPort,
				dns,
			}, nil
		default:
			if srcPort == 53 || dstPort == 53 {
				return nil, nil // TCP packets (connection related), no event
			}
		}

		return nil, fmt.Errorf("not a DNS packet")
	}
}

//
// DNS protocol type conversion (from gopacket layer to trace type)
//

func copyDNSToProtoDNS(l7 *layers.DNS, proto *trace.ProtoDNS) {
	proto.ID = l7.ID
	proto.QR = boolToUint8(l7.QR)
	proto.OpCode = strToLower(l7.OpCode.String())

	proto.AA = boolToUint8(l7.AA)
	proto.TC = boolToUint8(l7.TC)
	proto.RD = boolToUint8(l7.RD)
	proto.RA = boolToUint8(l7.RA)
	proto.Z = l7.Z

	proto.ResponseCode = strToLower(l7.ResponseCode.String())
	proto.QDCount = l7.QDCount
	proto.ANCount = l7.ANCount
	proto.NSCount = l7.NSCount
	proto.ARCount = l7.ARCount

	// process all existing questions (if any)
	for _, i := range l7.Questions {
		proto.Questions = append(proto.Questions,
			trace.ProtoDNSQuestion{
				Name:  string(i.Name),
				Type:  i.Type.String(),
				Class: i.Class.String(),
			})
	}
	// process all existing answers (if any)
	for _, i := range l7.Answers {
		proto.Answers = append(
			proto.Answers,
			newProtoDNSResourceRecord(i),
		)
	}
	// process all existing authorities (if any)
	for _, i := range l7.Authorities {
		proto.Authorities = append(
			proto.Authorities,
			newProtoDNSResourceRecord(i),
		)
	}
	// process all existing additionals (if any)
	for _, i := range l7.Additionals {
		proto.Additionals = append(
			proto.Additionals,
			newProtoDNSResourceRecord(i),
		)
	}
}

func newProtoDNSResourceRecord(j layers.DNSResourceRecord) trace.ProtoDNSResourceRecord {
	r := trace.ProtoDNSResourceRecord{
		Name:  string(j.Name),
		Type:  j.Type.String(),
		Class: j.Class.String(),
		TTL:   j.TTL,
		IP:    j.IP.String(),
		NS:    string(j.NS),
		CNAME: string(j.CNAME),
		PTR:   string(j.PTR),
		TXTs:  convertArrayOfBytes(j.TXTs),
		SOA: trace.ProtoDNSSOA{
			MName:   string(j.SOA.MName),
			RName:   string(j.SOA.RName),
			Serial:  j.SOA.Serial,
			Refresh: j.SOA.Refresh,
			Retry:   j.SOA.Retry,
			Expire:  j.SOA.Expire,
			Minimum: j.SOA.Minimum,
		},
		SRV: trace.ProtoDNSSRV{
			Priority: j.SRV.Priority,
			Weight:   j.SRV.Weight,
			Port:     j.SRV.Port,
			Name:     string(j.SRV.Name),
		},
		MX: trace.ProtoDNSMX{
			Preference: j.MX.Preference,
			Name:       string(j.MX.Name),
		},
		OPT: convertArrayOfDNSOPT(j.OPT),
		URI: trace.ProtoDNSURI{
			Priority: j.URI.Priority,
			Weight:   j.URI.Weight,
			Target:   string(j.URI.Target),
		},
		TXT: string(j.TXT),
	}

	return r
}

// helpers

func convertArrayOfDNSOPT(given []layers.DNSOPT) []trace.ProtoDNSOPT {
	var res []trace.ProtoDNSOPT

	for _, i := range given {
		res = append(res, trace.ProtoDNSOPT{
			Code: i.Code.String(),
			Data: string(i.Data),
		})
	}

	return res
}
