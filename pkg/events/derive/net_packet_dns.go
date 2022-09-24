package derive

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

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
			var l7json customDNS
			copyDNStoCustomDNS(l7, &l7json)
			dns, _ := json.Marshal(l7json)

			return []interface{}{
				srcIP,
				dstIP,
				srcPort,
				dstPort,
				string(dns),
			}, nil
		default:
			if srcPort == 53 || dstPort == 53 {
				return nil, nil // TCP packets (connection related)
			}
		}

		return nil, fmt.Errorf("not a DNS packet")
	}
}

// DNS json equivalent types for complete L7 protocol marshalling

func copyDNStoCustomDNS(l7 *layers.DNS, custom *customDNS) {
	custom.ID = l7.ID
	custom.QR = boolToUint8(l7.QR)
	custom.OpCode = strToLower(l7.OpCode.String())

	custom.AA = boolToUint8(l7.AA)
	custom.TC = boolToUint8(l7.TC)
	custom.RD = boolToUint8(l7.RD)
	custom.RA = boolToUint8(l7.RA)
	custom.Z = l7.Z

	custom.ResponseCode = strToLower(l7.ResponseCode.String())
	custom.QDCount = l7.QDCount
	custom.ANCount = l7.ANCount
	custom.NSCount = l7.NSCount
	custom.ARCount = l7.ARCount

	// process all existing questions (if any)
	for _, i := range l7.Questions {
		custom.Questions = append(custom.Questions,
			customDNSQuestion{
				Name:  string(i.Name),
				Type:  i.Type.String(),
				Class: i.Class.String(),
			})
	}
	// process all existing answers (if any)
	for _, i := range l7.Answers {
		custom.Answers = append(
			custom.Answers,
			newCustomDNSResourceRecord(i),
		)
	}
	// process all existing authorities (if any)
	for _, i := range l7.Authorities {
		custom.Authorities = append(
			custom.Authorities,
			newCustomDNSResourceRecord(i),
		)
	}
	// process all existing additionals (if any)
	for _, i := range l7.Additionals {
		custom.Additionals = append(
			custom.Additionals,
			newCustomDNSResourceRecord(i),
		)
	}
}

func newCustomDNSResourceRecord(j layers.DNSResourceRecord) customDNSResourceRecord {
	r := customDNSResourceRecord{
		Name:  string(j.Name),
		Type:  j.Type.String(),
		Class: j.Class.String(),
		TTL:   j.TTL,
		IP:    j.IP.String(),
		NS:    string(j.NS),
		CNAME: string(j.CNAME),
		PTR:   string(j.PTR),
		TXTs:  convertArrayOfBytes(j.TXTs),
		SOA: customDNSSOA{
			MName:   string(j.SOA.MName),
			RName:   string(j.SOA.RName),
			Serial:  j.SOA.Serial,
			Refresh: j.SOA.Refresh,
			Retry:   j.SOA.Retry,
			Expire:  j.SOA.Expire,
			Minimum: j.SOA.Minimum,
		},
		SRV: customDNSSRV{
			Priority: j.SRV.Priority,
			Weight:   j.SRV.Weight,
			Port:     j.SRV.Port,
			Name:     string(j.SRV.Name),
		},
		MX: customDNSMX{
			Preference: j.MX.Preference,
			Name:       string(j.MX.Name),
		},
		OPT: convertArrayOfDNSOPT(j.OPT),
		URI: customDNSURI{
			Priority: j.URI.Priority,
			Weight:   j.URI.Weight,
			Target:   string(j.URI.Target),
		},
		TXT: string(j.TXT),
	}

	return r
}

type customDNS struct {
	ID           uint16                    `json:""`
	QR           uint8                     `json:"qr"`
	OpCode       string                    `json:"opcode"`
	AA           uint8                     `json:"aa"`
	TC           uint8                     `json:"tc"`
	RD           uint8                     `json:"rd"`
	RA           uint8                     `json:"ra"`
	Z            uint8                     `json:"z"`
	ResponseCode string                    `json:"rcode"`
	QDCount      uint16                    `json:"qdcount"`
	ANCount      uint16                    `json:"ancount"`
	NSCount      uint16                    `json:"nscount"`
	ARCount      uint16                    `json:"arcount"`
	Questions    []customDNSQuestion       `json:"questions"`
	Answers      []customDNSResourceRecord `json:"answers"`
	Authorities  []customDNSResourceRecord `json:"authorities"`
	Additionals  []customDNSResourceRecord `json:"additionals"`
}

type customDNSQuestion struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type customDNSResourceRecord struct {
	Name  string         `json:"name"`
	Type  string         `json:"type"`
	Class string         `json:"class"`
	TTL   uint32         `json:"ttl"`
	IP    string         `json:"IP"`
	NS    string         `json:"NS"`
	CNAME string         `json:"CNAME"`
	PTR   string         `json:"PTR"`
	TXTs  []string       `json:"TXTs"`
	SOA   customDNSSOA   `json:"SOA"`
	SRV   customDNSSRV   `json:"SRV"`
	MX    customDNSMX    `json:"MX"`
	OPT   []customDNSOPT `json:"OPT"`
	URI   customDNSURI   `json:"URI"`
	TXT   string         `json:"TXT"`
}

type customDNSSOA struct {
	MName   string `json:"MName"`
	RName   string `json:"RName"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

type customDNSSRV struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Name     string `json:"name"`
}

type customDNSMX struct {
	Preference uint16 `json:"preference"`
	Name       string `json:"name"`
}

type customDNSURI struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Target   string `json:"target"`
}

type customDNSOPT struct {
	Code string `json:"code"`
	Data string `json:"data"`
}

// helpers

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func convertArrayOfBytes(given [][]byte) []string {
	var res []string

	for _, i := range given {
		res = append(res, string(i))
	}

	return res
}

func convertArrayOfDNSOPT(given []layers.DNSOPT) []customDNSOPT {
	var res []customDNSOPT

	for _, i := range given {
		res = append(res, customDNSOPT{
			Code: i.Code.String(),
			Data: string(i.Data),
		})
	}

	return res
}

func strToLower(given string) string {
	return strings.ToLower(given)
}
