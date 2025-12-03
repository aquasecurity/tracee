package v1beta1

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Buffer pool for JSON marshaling to reduce allocations
var bufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 2048)) // 2KB initial capacity
	},
}

// Custom JSON marshaler for Event for high performance
// This replaces the slow reflection-based protojson marshaler
func (e *Event) MarshalJSON() ([]byte, error) {
	buf, ok := bufferPool.Get().(*bytes.Buffer)
	if !ok {
		buf = bytes.NewBuffer(make([]byte, 0, 2048))
	}
	buf.Reset()
	defer bufferPool.Put(buf)

	// Recover from panics to prevent crashing the entire process
	var panicErr error
	defer func() {
		if r := recover(); r != nil {
			// Convert panic to error so it can be logged properly
			panicErr = fmt.Errorf("panic in MarshalJSON for event %d (%s): %v", e.Id, e.Name, r)
		}
	}()

	buf.WriteByte('{')

	// Timestamp (always present)
	buf.WriteString(`"timestamp":"`)
	writeTimestamp(buf, e.Timestamp)
	buf.WriteByte('"')

	// ID
	buf.WriteString(`,"id":`)
	writeInt(buf, int64(e.Id))

	// Name
	buf.WriteString(`,"name":"`)
	writeEscapedString(buf, e.Name)
	buf.WriteByte('"')

	// Policies (optional)
	if e.Policies != nil {
		buf.WriteString(`,"policies":`)
		writePolicies(buf, e.Policies)
	}

	// Workload (optional, but usually present)
	if e.Workload != nil {
		buf.WriteString(`,"workload":`)
		writeWorkload(buf, e.Workload)
	}

	// Data array (event values)
	if len(e.Data) > 0 {
		buf.WriteString(`,"data":[`)
		for i, val := range e.Data {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeEventValue(buf, val)
		}
		buf.WriteByte(']')
	}

	// Threat (optional, for signature events)
	if e.Threat != nil {
		buf.WriteString(`,"threat":`)
		writeThreat(buf, e.Threat)
	}

	// DetectedFrom (optional, for signature-on-signature events)
	if e.DetectedFrom != nil {
		buf.WriteString(`,"detected_from":`)
		writeDetectedFrom(buf, e.DetectedFrom)
	}

	buf.WriteByte('}')

	// Check if panic occurred
	if panicErr != nil {
		return nil, panicErr
	}

	// Return a copy to avoid issues after buffer is returned to pool
	return append([]byte(nil), buf.Bytes()...), nil
}

// writeInt writes an integer to the buffer
func writeInt(buf *bytes.Buffer, n int64) {
	buf.WriteString(strconv.FormatInt(n, 10))
}

// writeUint writes an unsigned integer to the buffer
func writeUint(buf *bytes.Buffer, n uint64) {
	buf.WriteString(strconv.FormatUint(n, 10))
}

// writeUint32 writes a uint32 to the buffer
func writeUint32(buf *bytes.Buffer, n uint32) {
	buf.WriteString(strconv.FormatUint(uint64(n), 10))
}

// writeBool writes a boolean to the buffer
func writeBool(buf *bytes.Buffer, b bool) {
	if b {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
}

// writeEscapedString writes a JSON-escaped string to the buffer
func writeEscapedString(buf *bytes.Buffer, s string) {
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexChar(byte(r) >> 4))
				buf.WriteByte(hexChar(byte(r) & 0xF))
			} else {
				buf.WriteRune(r)
			}
		}
	}
}

func hexChar(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'a' + b - 10
}

// writeTimestamp writes a protobuf timestamp as RFC3339 string
func writeTimestamp(buf *bytes.Buffer, ts *timestamppb.Timestamp) {
	if ts == nil {
		buf.WriteString("null")
		return
	}
	// Convert to time.Time and format as RFC3339
	t := time.Unix(ts.Seconds, int64(ts.Nanos)).UTC()
	buf.WriteString(t.Format(time.RFC3339Nano))
}

// writePolicies writes the Policies message
func writePolicies(buf *bytes.Buffer, p *Policies) {
	if p == nil {
		buf.WriteString("null")
		return
	}
	buf.WriteByte('{')
	buf.WriteString(`"matched":[`)
	for i, policy := range p.Matched {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteByte('"')
		writeEscapedString(buf, policy)
		buf.WriteByte('"')
	}
	buf.WriteString("]}")
}

// Placeholder functions - will implement in next steps
func writeWorkload(buf *bytes.Buffer, w *Workload) {
	if w == nil {
		buf.WriteString("null")
		return
	}
	buf.WriteByte('{')
	first := true

	// Process
	if w.Process != nil {
		buf.WriteString(`"process":`)
		writeProcess(buf, w.Process)
		first = false
	}

	// Container
	if w.Container != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"container":`)
		writeContainer(buf, w.Container)
		first = false
	}

	// K8s
	if w.K8S != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"k8s":`)
		writeK8s(buf, w.K8S)
	}

	buf.WriteByte('}')
}

func writeProcess(buf *bytes.Buffer, p *Process) {
	if p == nil {
		buf.WriteString("null")
		return
	}
	buf.WriteByte('{')
	first := true

	if p.Executable != nil {
		buf.WriteString(`"executable":{"path":"`)
		writeEscapedString(buf, p.Executable.Path)
		buf.WriteString(`"}`)
		first = false
	}

	if p.UniqueId != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"unique_id":`)
		writeUint32(buf, p.UniqueId.Value)
		first = false
	}

	if p.HostPid != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"host_pid":`)
		writeUint32(buf, p.HostPid.Value)
		first = false
	}

	if p.Pid != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"pid":`)
		writeUint32(buf, p.Pid.Value)
		first = false
	}

	if p.RealUser != nil && p.RealUser.Id != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"real_user":{"id":`)
		writeUint32(buf, p.RealUser.Id.Value)
		buf.WriteByte('}')
		first = false
	}

	if p.Thread != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"thread":`)
		writeThread(buf, p.Thread)
		first = false
	}

	if len(p.Ancestors) > 0 {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"ancestors":[`)
		for i, ancestor := range p.Ancestors {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeProcess(buf, ancestor)
		}
		buf.WriteByte(']')
	}

	buf.WriteByte('}')
}

func writeThread(buf *bytes.Buffer, t *Thread) {
	if t == nil {
		buf.WriteString("null")
		return
	}
	buf.WriteByte('{')
	first := true

	if t.StartTime != nil {
		buf.WriteString(`"start_time":"`)
		writeTimestamp(buf, t.StartTime)
		buf.WriteByte('"')
		first = false
	}

	if t.Name != "" {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"name":"`)
		writeEscapedString(buf, t.Name)
		buf.WriteByte('"')
		first = false
	}

	if t.UniqueId != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"unique_id":`)
		writeUint32(buf, t.UniqueId.Value)
		first = false
	}

	if t.HostTid != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"host_tid":`)
		writeUint32(buf, t.HostTid.Value)
		first = false
	}

	if t.Tid != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"tid":`)
		writeUint32(buf, t.Tid.Value)
		first = false
	}

	if t.Syscall != "" {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"syscall":"`)
		writeEscapedString(buf, t.Syscall)
		buf.WriteByte('"')
		first = false
	}

	if t.Compat {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"compat":true`)
		first = false
	}

	if t.UserStackTrace != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"user_stack_trace":{"addresses":[`)
		for i, addr := range t.UserStackTrace.Addresses {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(`{"address":`)
			writeUint(buf, addr.Address)
			buf.WriteString(`,"symbol":"`)
			writeEscapedString(buf, addr.Symbol)
			buf.WriteString(`"}`)
		}
		buf.WriteString("]}")
	}

	buf.WriteByte('}')
}

func writeContainer(buf *bytes.Buffer, c *Container) {
	if c == nil {
		buf.WriteString("null")
		return
	}
	buf.WriteByte('{')
	buf.WriteString(`"id":"`)
	writeEscapedString(buf, c.Id)
	buf.WriteString(`","name":"`)
	writeEscapedString(buf, c.Name)
	buf.WriteString(`"`)

	if c.Image != nil {
		buf.WriteString(`,"image":{"id":"`)
		writeEscapedString(buf, c.Image.Id)
		buf.WriteString(`"`)

		if len(c.Image.RepoDigests) > 0 {
			buf.WriteString(`,"repo_digests":[`)
			for i, digest := range c.Image.RepoDigests {
				if i > 0 {
					buf.WriteByte(',')
				}
				buf.WriteByte('"')
				writeEscapedString(buf, digest)
				buf.WriteByte('"')
			}
			buf.WriteByte(']')
		}

		buf.WriteString(`,"name":"`)
		writeEscapedString(buf, c.Image.Name)
		buf.WriteString(`"}`)
	}

	buf.WriteString(`,"started":`)
	writeBool(buf, c.Started)
	buf.WriteByte('}')
}

func writeK8s(buf *bytes.Buffer, k *K8S) {
	if k == nil {
		buf.WriteString("null")
		return
	}
	buf.WriteByte('{')
	first := true

	if k.Pod != nil {
		buf.WriteString(`"pod":{"name":"`)
		writeEscapedString(buf, k.Pod.Name)
		buf.WriteString(`","uid":"`)
		writeEscapedString(buf, k.Pod.Uid)
		buf.WriteByte('"')

		if len(k.Pod.Labels) > 0 {
			buf.WriteString(`,"labels":{`)
			i := 0
			for key, val := range k.Pod.Labels {
				if i > 0 {
					buf.WriteByte(',')
				}
				buf.WriteByte('"')
				writeEscapedString(buf, key)
				buf.WriteString(`":"`)
				writeEscapedString(buf, val)
				buf.WriteByte('"')
				i++
			}
			buf.WriteByte('}')
		}

		buf.WriteByte('}')
		first = false
	}

	if k.Namespace != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"namespace":{"name":"`)
		writeEscapedString(buf, k.Namespace.Name)
		buf.WriteString(`"}`)
	}

	buf.WriteByte('}')
}

func writeThreat(buf *bytes.Buffer, t *Threat) {
	buf.WriteByte('{')
	buf.WriteString(`"description":"`)
	writeEscapedString(buf, t.Description)
	buf.WriteString(`"`)

	if t.Mitre != nil {
		buf.WriteString(`,"mitre":{`)
		if t.Mitre.Tactic != nil {
			buf.WriteString(`"tactic":{"name":"`)
			writeEscapedString(buf, t.Mitre.Tactic.Name)
			buf.WriteString(`"}`)
		}
		if t.Mitre.Technique != nil {
			if t.Mitre.Tactic != nil {
				buf.WriteByte(',')
			}
			buf.WriteString(`"technique":{"id":"`)
			writeEscapedString(buf, t.Mitre.Technique.Id)
			buf.WriteString(`","name":"`)
			writeEscapedString(buf, t.Mitre.Technique.Name)
			buf.WriteString(`"}`)
		}
		buf.WriteByte('}')
	}

	buf.WriteString(`,"severity":`)
	writeInt(buf, int64(t.Severity))

	buf.WriteString(`,"name":"`)
	writeEscapedString(buf, t.Name)
	buf.WriteByte('"')

	if len(t.Properties) > 0 {
		buf.WriteString(`,"properties":{`)
		i := 0
		for key, val := range t.Properties {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteByte('"')
			writeEscapedString(buf, key)
			buf.WriteString(`":"`)
			writeEscapedString(buf, val)
			buf.WriteByte('"')
			i++
		}
		buf.WriteByte('}')
	}

	buf.WriteByte('}')
}

func writeDetectedFrom(buf *bytes.Buffer, d *DetectedFrom) {
	buf.WriteByte('{')
	buf.WriteString(`"id":`)
	writeUint32(buf, d.Id)
	buf.WriteString(`,"name":"`)
	writeEscapedString(buf, d.Name)
	buf.WriteByte('"')

	if len(d.Data) > 0 {
		buf.WriteString(`,"data":[`)
		for i, val := range d.Data {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeEventValue(buf, val)
		}
		buf.WriteByte(']')
	}

	if d.Parent != nil {
		buf.WriteString(`,"parent":`)
		writeDetectedFrom(buf, d.Parent)
	}

	buf.WriteByte('}')
}

func writeEventValue(buf *bytes.Buffer, ev *EventValue) {
	buf.WriteByte('{')
	buf.WriteString(`"name":"`)
	writeEscapedString(buf, ev.Name)
	buf.WriteString(`"`)

	// Write the value based on the oneof type
	switch v := ev.Value.(type) {
	case *EventValue_Int32:
		buf.WriteString(`,"value":`)
		writeInt(buf, int64(v.Int32))
	case *EventValue_Int64:
		buf.WriteString(`,"value":`)
		writeInt(buf, v.Int64)
	case *EventValue_UInt32:
		buf.WriteString(`,"value":`)
		writeUint32(buf, v.UInt32)
	case *EventValue_UInt64:
		buf.WriteString(`,"value":`)
		writeUint(buf, v.UInt64)
	case *EventValue_Str:
		buf.WriteString(`,"value":"`)
		writeEscapedString(buf, v.Str)
		buf.WriteByte('"')
	case *EventValue_Bytes:
		buf.WriteString(`,"value":"`)
		buf.WriteString(base64.StdEncoding.EncodeToString(v.Bytes))
		buf.WriteByte('"')
	case *EventValue_Bool:
		buf.WriteString(`,"value":`)
		writeBool(buf, v.Bool)
	case *EventValue_StrArray:
		buf.WriteString(`,"value":[`)
		for i, s := range v.StrArray.Value {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteByte('"')
			writeEscapedString(buf, s)
			buf.WriteByte('"')
		}
		buf.WriteByte(']')
	case *EventValue_Int32Array:
		buf.WriteString(`,"value":[`)
		for i, n := range v.Int32Array.Value {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeInt(buf, int64(n))
		}
		buf.WriteByte(']')
	case *EventValue_UInt64Array:
		buf.WriteString(`,"value":[`)
		for i, n := range v.UInt64Array.Value {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeUint(buf, n)
		}
		buf.WriteByte(']')
	case *EventValue_Sockaddr:
		buf.WriteString(`,"value":`)
		writeSockAddr(buf, v.Sockaddr)
	case *EventValue_Credentials:
		buf.WriteString(`,"value":`)
		writeCredentials(buf, v.Credentials)
	case *EventValue_Timespec:
		buf.WriteString(`,"value":`)
		writeTimespec(buf, v.Timespec)
	case *EventValue_Struct:
		buf.WriteString(`,"value":`)
		writeStruct(buf, v.Struct)
	// Complex network types - use json.Marshal fallback (rare, performance not critical)
	case *EventValue_HookedSyscalls:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.HookedSyscalls)
	case *EventValue_HookedSeqOps:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.HookedSeqOps)
	case *EventValue_Ipv4:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.Ipv4)
	case *EventValue_Ipv6:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.Ipv6)
	case *EventValue_Tcp:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.Tcp)
	case *EventValue_Udp:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.Udp)
	case *EventValue_Icmp:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.Icmp)
	case *EventValue_Icmpv6:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.Icmpv6)
	case *EventValue_Dns:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.Dns)
	case *EventValue_DnsQuestions:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.DnsQuestions)
	case *EventValue_DnsResponses:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.DnsResponses)
	case *EventValue_PacketMetadata:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.PacketMetadata)
	case *EventValue_Http:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.Http)
	case *EventValue_HttpRequest:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.HttpRequest)
	case *EventValue_HttpResponse:
		buf.WriteString(`,"value":`)
		writeJSONFallback(buf, v.HttpResponse)
	default:
		// Unknown type - write null
		buf.WriteString(`,"value":null`)
	}

	buf.WriteByte('}')
}

// writeSockAddr writes a socket address
func writeSockAddr(buf *bytes.Buffer, sa *SockAddr) {
	if sa == nil {
		buf.WriteString("null")
		return
	}
	buf.WriteByte('{')
	buf.WriteString(`"sa_family":`)
	writeInt(buf, int64(sa.SaFamily))

	if sa.SunPath != "" {
		buf.WriteString(`,"sun_path":"`)
		writeEscapedString(buf, sa.SunPath)
		buf.WriteByte('"')
	}
	if sa.SinAddr != "" {
		buf.WriteString(`,"sin_addr":"`)
		writeEscapedString(buf, sa.SinAddr)
		buf.WriteByte('"')
	}
	if sa.SinPort != 0 {
		buf.WriteString(`,"sin_port":`)
		writeUint32(buf, sa.SinPort)
	}
	if sa.Sin6Addr != "" {
		buf.WriteString(`,"sin6_addr":"`)
		writeEscapedString(buf, sa.Sin6Addr)
		buf.WriteByte('"')
	}
	if sa.Sin6Port != 0 {
		buf.WriteString(`,"sin6_port":`)
		writeUint32(buf, sa.Sin6Port)
	}
	if sa.Sin6Flowinfo != 0 {
		buf.WriteString(`,"sin6_flowinfo":`)
		writeUint32(buf, sa.Sin6Flowinfo)
	}
	if sa.Sin6Scopeid != 0 {
		buf.WriteString(`,"sin6_scopeid":`)
		writeUint32(buf, sa.Sin6Scopeid)
	}
	buf.WriteByte('}')
}

// writeCredentials writes process credentials
func writeCredentials(buf *bytes.Buffer, c *Credentials) {
	if c == nil {
		buf.WriteString("null")
		return
	}
	buf.WriteByte('{')
	first := true

	if c.Uid != nil {
		buf.WriteString(`"uid":`)
		writeUint32(buf, c.Uid.Value)
		first = false
	}
	if c.Gid != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"gid":`)
		writeUint32(buf, c.Gid.Value)
		first = false
	}
	if c.Suid != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"suid":`)
		writeUint32(buf, c.Suid.Value)
		first = false
	}
	if c.Sgid != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"sgid":`)
		writeUint32(buf, c.Sgid.Value)
		first = false
	}
	if c.Euid != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"euid":`)
		writeUint32(buf, c.Euid.Value)
		first = false
	}
	if c.Egid != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"egid":`)
		writeUint32(buf, c.Egid.Value)
		first = false
	}
	if c.Fsuid != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"fsuid":`)
		writeUint32(buf, c.Fsuid.Value)
		first = false
	}
	if c.Fsgid != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"fsgid":`)
		writeUint32(buf, c.Fsgid.Value)
		first = false
	}
	if c.UserNamespace != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"user_namespace":`)
		writeUint32(buf, c.UserNamespace.Value)
		first = false
	}
	if c.SecureBits != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"secure_bits":`)
		writeUint32(buf, c.SecureBits.Value)
		first = false
	}

	// Capability arrays
	if len(c.CapInheritable) > 0 {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"cap_inheritable":[`)
		for i, cap := range c.CapInheritable {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeInt(buf, int64(cap))
		}
		buf.WriteByte(']')
		first = false
	}
	if len(c.CapPermitted) > 0 {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"cap_permitted":[`)
		for i, cap := range c.CapPermitted {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeInt(buf, int64(cap))
		}
		buf.WriteByte(']')
		first = false
	}
	if len(c.CapEffective) > 0 {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"cap_effective":[`)
		for i, cap := range c.CapEffective {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeInt(buf, int64(cap))
		}
		buf.WriteByte(']')
		first = false
	}
	if len(c.CapBounding) > 0 {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"cap_bounding":[`)
		for i, cap := range c.CapBounding {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeInt(buf, int64(cap))
		}
		buf.WriteByte(']')
		first = false
	}
	if len(c.CapAmbient) > 0 {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"cap_ambient":[`)
		for i, cap := range c.CapAmbient {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeInt(buf, int64(cap))
		}
		buf.WriteByte(']')
	}

	buf.WriteByte('}')
}

// writeTimespec writes a timespec
func writeTimespec(buf *bytes.Buffer, ts *Timespec) {
	if ts == nil || ts.Value == nil {
		buf.WriteString("null")
		return
	}
	buf.WriteByte('{')
	buf.WriteString(`"value":`)
	buf.WriteString(strconv.FormatFloat(ts.Value.Value, 'g', -1, 64))
	buf.WriteByte('}')
}

// writeJSONFallback uses encoding/json for complex types (acceptable since they're rare)
func writeJSONFallback(buf *bytes.Buffer, v interface{}) {
	if v == nil {
		buf.WriteString("null")
		return
	}
	// Use encoding/json as fallback for complex network types
	// This is acceptable since these types are rare and won't affect overall performance
	data, err := json.Marshal(v)
	if err != nil {
		buf.WriteString("null")
		return
	}
	buf.Write(data)
}

// writeStruct writes a google.protobuf.Struct
// This is a map[string]interface{} equivalent
func writeStruct(buf *bytes.Buffer, s *structpb.Struct) {
	if s == nil || s.Fields == nil {
		buf.WriteString("null")
		return
	}

	buf.WriteByte('{')
	first := true
	for key, val := range s.Fields {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteByte('"')
		writeEscapedString(buf, key)
		buf.WriteString(`":`)
		writeValue(buf, val)
		first = false
	}
	buf.WriteByte('}')
}

// writeValue writes a google.protobuf.Value
func writeValue(buf *bytes.Buffer, v *structpb.Value) {
	if v == nil {
		buf.WriteString("null")
		return
	}

	switch k := v.Kind.(type) {
	case *structpb.Value_NullValue:
		buf.WriteString("null")
	case *structpb.Value_NumberValue:
		buf.WriteString(strconv.FormatFloat(k.NumberValue, 'g', -1, 64))
	case *structpb.Value_StringValue:
		buf.WriteByte('"')
		writeEscapedString(buf, k.StringValue)
		buf.WriteByte('"')
	case *structpb.Value_BoolValue:
		writeBool(buf, k.BoolValue)
	case *structpb.Value_StructValue:
		writeStruct(buf, k.StructValue)
	case *structpb.Value_ListValue:
		buf.WriteByte('[')
		for i, item := range k.ListValue.Values {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeValue(buf, item)
		}
		buf.WriteByte(']')
	default:
		buf.WriteString("null")
	}
}
