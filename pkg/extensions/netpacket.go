package extensions

import (
	"kernel.org/pub/linux/libs/security/libcap/cap"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

func initNetPacket() {
	// NOTE: netpacket already has its own event definitions and probes.
	// TODO: netpacket needs its own bpf module (objs for maps and objs for progs).

	err := Definitions.AddBatch("netpacket", netPacketEvents)
	if err != nil {
		logger.Errorw("failed to initialize event definitions", "err", err)
	}
	netPacketProbes()
}

const (
	NetPacketBase int = iota + 700
	NetPacketIPBase
	NetPacketTCPBase
	NetPacketUDPBase
	NetPacketICMPBase
	NetPacketICMPv6Base
	NetPacketDNSBase
	NetPacketHTTPBase
	NetPacketCapture
	NetPacketFlow
	MaxNetID // network base events go ABOVE this item
)

// Events originated from user-space
const (
	NetPacketIPv4 int = iota + 2000
	NetPacketIPv6
	NetPacketTCP
	NetPacketUDP
	NetPacketICMP
	NetPacketICMPv6
	NetPacketDNS
	NetPacketDNSRequest
	NetPacketDNSResponse
	NetPacketHTTP
	NetPacketHTTPRequest
	NetPacketHTTPResponse
	NetFlowEnd
	NetFlowTCPBegin
	NetFlowTCPEnd
	MaxUserNetID
)

// Event Probe Handles
const (
	ProbeSockAllocFile int = iota
	ProbeSockAllocFileRet
	ProbeSecuritySkClone
	ProbeSecuritySocketRecvmsg
	ProbeSecuritySocketSendmsg
	ProbeCgroupBPFRunFilterSKB
	ProbeCgroupSKBIngress
	ProbeCgroupSKBEgress
)

func netPacketProbes() {
	Probes.Add("netpacket", ProbeSockAllocFile, NewTraceProbe(KProbe, "sock_alloc_file", "trace_sock_alloc_file"))
	Probes.Add("netpacket", ProbeSockAllocFileRet, NewTraceProbe(KretProbe, "sock_alloc_file", "trace_ret_sock_alloc_file"))
	Probes.Add("netpacket", ProbeSecuritySkClone, NewTraceProbe(KProbe, "security_sk_clone", "trace_security_sk_clone"))
	Probes.Add("netpacket", ProbeSecuritySocketSendmsg, NewTraceProbe(KProbe, "security_socket_sendmsg", "trace_security_socket_sendmsg"))
	Probes.Add("netpacket", ProbeSecuritySocketRecvmsg, NewTraceProbe(KProbe, "security_socket_recvmsg", "trace_security_socket_recvmsg"))
	Probes.Add("netpacket", ProbeCgroupBPFRunFilterSKB, NewTraceProbe(KProbe, "__cgroup_bpf_run_filter_skb", "cgroup_bpf_run_filter_skb"))
	Probes.Add("netpacket", ProbeCgroupSKBIngress, NewCgroupProbe(bpf.BPFAttachTypeCgroupInetIngress, "cgroup_skb_ingress"))
	Probes.Add("netpacket", ProbeCgroupSKBEgress, NewCgroupProbe(bpf.BPFAttachTypeCgroupInetEgress, "cgroup_skb_egress"))
}

var netPacketEvents = map[int]Definition{
	//
	// Begin of Network Protocol Event Types
	//
	NetPacketBase: {
		id:       NetPacketBase,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			capabilities: CapsDep{
				ebpf: []cap.Value{
					cap.NET_ADMIN, // needed for BPF_PROG_TYPE_CGROUP_SKB
				},
			},
			probes: []ProbeDep{
				{handle: ProbeCgroupSKBIngress, required: true},
				{handle: ProbeCgroupSKBEgress, required: true},
				{handle: ProbeSockAllocFile, required: true},
				{handle: ProbeSockAllocFileRet, required: true},
				{handle: ProbeCgroupBPFRunFilterSKB, required: true},
				{handle: ProbeSecuritySocketRecvmsg, required: true},
				{handle: ProbeSecuritySocketSendmsg, required: true},
				{handle: ProbeSecuritySkClone, required: true},
			},
		},
		sets:   []string{"network_events"},
		params: []trace.ArgMeta{},
	},
	NetPacketIPBase: {
		id:       NetPacketIPBase,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_ip_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []int{
				NetPacketBase,
			},
		},
		sets: []string{"network_events"},
		params: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetPacketIPv4: {
		id:      NetPacketIPv4,
		id32Bit: Sys32Undefined,
		name:    "net_packet_ipv4",
		version: NewVersion(1, 1, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketIPBase,
			},
		},
		sets: []string{"network_events"},
		params: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoIPv4", Name: "proto_ipv4"},
		},
	},
	NetPacketIPv6: {
		id:      NetPacketIPv6,
		id32Bit: Sys32Undefined,
		name:    "net_packet_ipv6",
		version: NewVersion(1, 1, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketIPBase,
			},
		},
		sets: []string{"network_events"},
		params: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoIPv6", Name: "proto_ipv6"},
		},
	},
	NetPacketTCPBase: {
		id:       NetPacketTCPBase,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_tcp_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []int{
				NetPacketBase,
			},
		},
		sets: []string{"network_events"},
		params: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetPacketTCP: {
		id:      NetPacketTCP,
		id32Bit: Sys32Undefined,
		name:    "net_packet_tcp",
		version: NewVersion(1, 1, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketTCPBase,
			},
		},
		sets: []string{"network_events"},
		params: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "src_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "dst_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoTCP", Name: "proto_tcp"},
		},
	},
	NetPacketUDPBase: {
		id:       NetPacketUDPBase,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_udp_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []int{
				NetPacketBase,
			},
		},
		sets: []string{"network_events"},
		params: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetPacketUDP: {
		id:      NetPacketUDP,
		id32Bit: Sys32Undefined,
		name:    "net_packet_udp",
		version: NewVersion(1, 1, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketUDPBase,
			},
		},
		sets: []string{"network_events"},
		params: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "src_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "dst_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoUDP", Name: "proto_udp"},
		},
	},
	NetPacketICMPBase: {
		id:      NetPacketICMPBase,
		id32Bit: Sys32Undefined,
		name:    "net_packet_icmp_base",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketBase,
			},
		},
		internal: true,
		sets:     []string{"network_events"},
		params: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetPacketICMP: {
		id:      NetPacketICMP,
		id32Bit: Sys32Undefined,
		name:    "net_packet_icmp",
		version: NewVersion(1, 1, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketICMPBase,
			},
		},
		sets: []string{"default", "network_events"},
		params: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoICMP", Name: "proto_icmp"},
		},
	},
	NetPacketICMPv6Base: {
		id:       NetPacketICMPv6Base,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_icmpv6_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []int{
				NetPacketBase,
			},
		},
		sets: []string{"network_events"},
		params: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetPacketICMPv6: {
		id:      NetPacketICMPv6,
		id32Bit: Sys32Undefined,
		name:    "net_packet_icmpv6",
		version: NewVersion(1, 1, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketICMPv6Base,
			},
		},
		sets: []string{"default", "network_events"},
		params: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoICMPv6", Name: "proto_icmpv6"},
		},
	},
	NetPacketDNSBase: {
		id:       NetPacketDNSBase,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_dns_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []int{
				NetPacketBase,
			},
		},
		sets: []string{"network_events"},
		params: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetPacketDNS: {
		id:      NetPacketDNS,
		id32Bit: Sys32Undefined,
		name:    "net_packet_dns", // preferred event to write signatures
		version: NewVersion(1, 1, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketDNSBase,
			},
		},
		sets: []string{"network_events"},
		params: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "src_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "dst_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoDNS", Name: "proto_dns"},
		},
	},
	NetPacketDNSRequest: {
		id:      NetPacketDNSRequest,
		id32Bit: Sys32Undefined,
		name:    "net_packet_dns_request", // simple dns event compatible dns_request (deprecated)
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketDNSBase,
			},
		},
		sets: []string{"default", "network_events"},
		params: []trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
			{Type: "[]trace.DnsQueryData", Name: "dns_questions"},
		},
	},
	NetPacketDNSResponse: {
		id:      NetPacketDNSResponse,
		id32Bit: Sys32Undefined,
		name:    "net_packet_dns_response", // simple dns event compatible dns_response (deprecated)
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketDNSBase,
			},
		},
		sets: []string{"default", "network_events"},
		params: []trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
			{Type: "[]trace.DnsResponseData", Name: "dns_response"},
		},
	},
	NetPacketHTTPBase: {
		id:       NetPacketHTTPBase,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_http_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []int{
				NetPacketBase,
			},
		},
		sets: []string{"network_events"},
		params: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetPacketHTTP: {
		id:      NetPacketHTTP,
		id32Bit: Sys32Undefined,
		name:    "net_packet_http", // preferred event to write signatures
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketHTTPBase,
			},
		},
		sets: []string{"network_events"},
		params: []trace.ArgMeta{
			{Type: "const char*", Name: "src"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "const char*", Name: "dst"}, // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "src_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "u16", Name: "dst_port"},    // TODO: pack and remove into trace.PacketMetadata after it supports filtering
			{Type: "trace.PacketMetadata", Name: "metadata"},
			{Type: "trace.ProtoHTTP", Name: "proto_http"},
		},
	},
	NetPacketHTTPRequest: {
		id:      NetPacketHTTPRequest,
		id32Bit: Sys32Undefined,
		name:    "net_packet_http_request",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketHTTPBase,
			},
		},
		sets: []string{"default", "network_events"},
		params: []trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
			{Type: "trace.ProtoHTTPRequest", Name: "http_request"},
		},
	},
	NetPacketHTTPResponse: {
		id:      NetPacketHTTPResponse,
		id32Bit: Sys32Undefined,
		name:    "net_packet_http_response",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketHTTPBase,
			},
		},
		sets: []string{"default", "network_events"},
		params: []trace.ArgMeta{
			{Type: "trace.PktMeta", Name: "metadata"},
			{Type: "trace.ProtoHTTPResponse", Name: "http_response"},
		},
	},
	NetPacketCapture: {
		id:       NetPacketCapture, // Packets with full payload (sent in a dedicated perfbuffer)
		id32Bit:  Sys32Undefined,
		name:     "net_packet_capture",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []int{
				NetPacketBase,
			},
		},
		params: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	CaptureNetPacket: {
		id:       CaptureNetPacket, // Pseudo Event: used to capture packets
		id32Bit:  Sys32Undefined,
		name:     "capture_net_packet",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []int{
				NetPacketCapture,
			},
		},
	},
	NetPacketFlow: {
		id:       NetPacketFlow,
		id32Bit:  Sys32Undefined,
		name:     "net_packet_flow_base",
		version:  NewVersion(1, 0, 0),
		internal: true,
		dependencies: Dependencies{
			ids: []int{
				NetPacketBase,
			},
		},
		sets: []string{"network_events"},
		params: []trace.ArgMeta{
			{Type: "bytes", Name: "payload"},
		},
	},
	NetFlowTCPBegin: {
		id:      NetFlowTCPBegin,
		id32Bit: Sys32Undefined,
		name:    "net_flow_tcp_begin",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketFlow,
			},
		},
		sets: []string{"network_events", "flows"},
		params: []trace.ArgMeta{
			{Type: "const char*", Name: "conn_direction"},
			{Type: "const char*", Name: "src"},
			{Type: "const char*", Name: "dst"},
			{Type: "u16", Name: "src_port"},
			{Type: "u16", Name: "dst_port"},
			{Type: "const char **", Name: "src_dns"},
			{Type: "const char **", Name: "dst_dns"},
		},
	},
	NetFlowTCPEnd: {
		id:      NetFlowTCPEnd,
		id32Bit: Sys32Undefined,
		name:    "net_flow_tcp_end",
		version: NewVersion(1, 0, 0),
		dependencies: Dependencies{
			ids: []int{
				NetPacketFlow,
			},
		},
		sets: []string{"network_events", "flows"},
		params: []trace.ArgMeta{
			{Type: "const char*", Name: "conn_direction"},
			{Type: "const char*", Name: "src"},
			{Type: "const char*", Name: "dst"},
			{Type: "u16", Name: "src_port"},
			{Type: "u16", Name: "dst_port"},
			{Type: "const char **", Name: "src_dns"},
			{Type: "const char **", Name: "dst_dns"},
		},
	},
}
