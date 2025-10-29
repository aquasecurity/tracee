package events

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestConvertToProto_BasicFields(t *testing.T) {
	t.Parallel()

	execveID, _ := Core.GetDefinitionIDByName("execve")
	e := trace.Event{
		EventID:         int(execveID),
		EventName:       "execve",
		Timestamp:       1234567890,
		ProcessID:       1001,
		ProcessName:     "test_process",
		ThreadID:        1001,
		HostThreadID:    1001,
		ProcessEntityId: 12345,
		ThreadEntityId:  12345,
		UserID:          1000,
	}
	e.Executable.Path = "/usr/bin/test"

	protoEvent := ConvertToProto(&e)

	assert.NotNil(t, protoEvent)
	assert.Equal(t, "execve", protoEvent.Name)
	assert.Equal(t, pb.EventId(e.EventID), protoEvent.Id)
	assert.NotNil(t, protoEvent.Timestamp)
	require.NotNil(t, protoEvent.Workload)
	require.NotNil(t, protoEvent.Workload.Process)
	assert.Equal(t, "/usr/bin/test", protoEvent.Workload.Process.Executable.Path)
	assert.Equal(t, "test_process", protoEvent.Workload.Process.Thread.Name)
}

func TestConvertToProto_ContainerInfo(t *testing.T) {
	t.Parallel()

	e := trace.Event{
		EventID:     1,
		EventName:   "test_event",
		ProcessID:   1001,
		ContainerID: "abc123",
		Container: trace.Container{
			ID:          "abc123",
			Name:        "test_container",
			ImageName:   "ubuntu:22.04",
			ImageDigest: "sha256:abcdef123456",
		},
	}
	e.ContextFlags.ContainerStarted = true

	protoEvent := ConvertToProto(&e)

	require.NotNil(t, protoEvent.Workload)
	require.NotNil(t, protoEvent.Workload.Container)
	assert.Equal(t, "abc123", protoEvent.Workload.Container.Id)
	assert.Equal(t, "test_container", protoEvent.Workload.Container.Name)
	assert.True(t, protoEvent.Workload.Container.Started)
	require.NotNil(t, protoEvent.Workload.Container.Image)
	assert.Equal(t, "ubuntu:22.04", protoEvent.Workload.Container.Image.Name)
	assert.Contains(t, protoEvent.Workload.Container.Image.RepoDigests, "sha256:abcdef123456")
}

func TestConvertToProto_EventData_Primitives(t *testing.T) {
	t.Parallel()

	// Use a non-syscall event ID (container_create = 2018)
	e := trace.Event{
		EventID:   2018,
		EventName: "container_create",
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "int_val"}, Value: int(42)},
			{ArgMeta: trace.ArgMeta{Name: "int32_val"}, Value: int32(100)},
			{ArgMeta: trace.ArgMeta{Name: "uint32_val"}, Value: uint32(200)},
			{ArgMeta: trace.ArgMeta{Name: "int64_val"}, Value: int64(1000)},
			{ArgMeta: trace.ArgMeta{Name: "uint64_val"}, Value: uint64(2000)},
			{ArgMeta: trace.ArgMeta{Name: "bool_val"}, Value: true},
			{ArgMeta: trace.ArgMeta{Name: "str_val"}, Value: "hello"},
		},
	}

	protoEvent := ConvertToProto(&e)

	require.NotNil(t, protoEvent.Data)
	assert.Len(t, protoEvent.Data, 7)

	// Check individual values
	assert.Equal(t, "int_val", protoEvent.Data[0].Name)
	assert.Equal(t, int64(42), protoEvent.Data[0].GetInt64())

	assert.Equal(t, "int32_val", protoEvent.Data[1].Name)
	assert.Equal(t, int32(100), protoEvent.Data[1].GetInt32())

	assert.Equal(t, "uint32_val", protoEvent.Data[2].Name)
	assert.Equal(t, uint32(200), protoEvent.Data[2].GetUInt32())

	assert.Equal(t, "int64_val", protoEvent.Data[3].Name)
	assert.Equal(t, int64(1000), protoEvent.Data[3].GetInt64())

	assert.Equal(t, "uint64_val", protoEvent.Data[4].Name)
	assert.Equal(t, uint64(2000), protoEvent.Data[4].GetUInt64())

	assert.Equal(t, "bool_val", protoEvent.Data[5].Name)
	assert.True(t, protoEvent.Data[5].GetBool())

	assert.Equal(t, "str_val", protoEvent.Data[6].Name)
	assert.Equal(t, "hello", protoEvent.Data[6].GetStr())
}

func TestConvertToProto_EventData_Arrays(t *testing.T) {
	t.Parallel()

	// Use a non-syscall event ID
	e := trace.Event{
		EventID:   2018,
		EventName: "container_create",
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "str_array"}, Value: []string{"foo", "bar", "baz"}},
			{ArgMeta: trace.ArgMeta{Name: "uint64_array"}, Value: []uint64{1, 2, 3, 4, 5}},
			{ArgMeta: trace.ArgMeta{Name: "bytes"}, Value: []byte{0x01, 0x02, 0x03}},
		},
	}

	protoEvent := ConvertToProto(&e)

	require.NotNil(t, protoEvent.Data)
	assert.Len(t, protoEvent.Data, 3)

	assert.Equal(t, "str_array", protoEvent.Data[0].Name)
	assert.Equal(t, []string{"foo", "bar", "baz"}, protoEvent.Data[0].GetStrArray().Value)

	assert.Equal(t, "uint64_array", protoEvent.Data[1].Name)
	assert.Equal(t, []uint64{1, 2, 3, 4, 5}, protoEvent.Data[1].GetUInt64Array().Value)

	assert.Equal(t, "bytes", protoEvent.Data[2].Name)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, protoEvent.Data[2].GetBytes())
}

func TestConvertToProto_EventData_Credentials(t *testing.T) {
	t.Parallel()

	// Use a non-syscall event ID
	e := trace.Event{
		EventID:   2018,
		EventName: "container_create",
		Args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{Name: "creds"},
				Value: trace.SlimCred{
					Uid:          1000,
					Gid:          1000,
					Euid:         1001,
					Egid:         1001,
					CapEffective: 0x1FFFFFFFFFF,
					CapPermitted: 0x1FFFFFFFFFF,
				},
			},
		},
	}

	protoEvent := ConvertToProto(&e)

	require.NotNil(t, protoEvent.Data)
	assert.Len(t, protoEvent.Data, 1)

	assert.Equal(t, "creds", protoEvent.Data[0].Name)
	creds := protoEvent.Data[0].GetCredentials()
	require.NotNil(t, creds)
	assert.Equal(t, uint32(1000), creds.Uid.Value)
	assert.Equal(t, uint32(1000), creds.Gid.Value)
	assert.Equal(t, uint32(1001), creds.Euid.Value)
	assert.Equal(t, uint32(1001), creds.Egid.Value)
	assert.NotEmpty(t, creds.CapEffective)
	assert.NotEmpty(t, creds.CapPermitted)
}

func TestConvertToProto_EventData_NetworkIPv4(t *testing.T) {
	t.Parallel()

	// Use a non-syscall event ID
	e := trace.Event{
		EventID:   2000,
		EventName: "net_packet_ipv4",
		Args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{Name: "ipv4"},
				Value: trace.ProtoIPv4{
					Version:  4,
					IHL:      5,
					Protocol: "TCP",
					SrcIP:    "192.168.1.1",
					DstIP:    "192.168.1.2",
				},
			},
		},
	}

	protoEvent := ConvertToProto(&e)

	require.NotNil(t, protoEvent.Data)
	assert.Len(t, protoEvent.Data, 1)

	assert.Equal(t, "ipv4", protoEvent.Data[0].Name)
	ipv4 := protoEvent.Data[0].GetIpv4()
	require.NotNil(t, ipv4)
	assert.Equal(t, uint32(4), ipv4.Version)
	assert.Equal(t, "TCP", ipv4.Protocol)
	assert.Equal(t, "192.168.1.1", ipv4.SrcIp)
	assert.Equal(t, "192.168.1.2", ipv4.DstIp)
}

func TestConvertToProto_EventData_NetworkTCP(t *testing.T) {
	t.Parallel()

	// Use a non-syscall event ID
	e := trace.Event{
		EventID:   2002,
		EventName: "net_packet_tcp",
		Args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{Name: "tcp"},
				Value: trace.ProtoTCP{
					SrcPort: 8080,
					DstPort: 443,
					SYN:     1,
					ACK:     1,
				},
			},
		},
	}

	protoEvent := ConvertToProto(&e)

	require.NotNil(t, protoEvent.Data)
	assert.Len(t, protoEvent.Data, 1)

	assert.Equal(t, "tcp", protoEvent.Data[0].Name)
	tcp := protoEvent.Data[0].GetTcp()
	require.NotNil(t, tcp)
	assert.Equal(t, uint32(8080), tcp.SrcPort)
	assert.Equal(t, uint32(443), tcp.DstPort)
	assert.Equal(t, uint32(1), tcp.SynFlag)
	assert.Equal(t, uint32(1), tcp.AckFlag)
}

func TestConvertToProto_EventData_HTTP(t *testing.T) {
	t.Parallel()

	headers := http.Header{
		"Content-Type": []string{"application/json"},
		"User-Agent":   []string{"test-agent/1.0"},
	}

	// Use a non-syscall event ID
	e := trace.Event{
		EventID:   2009,
		EventName: "net_packet_http",
		Args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{Name: "http_request"},
				Value: trace.ProtoHTTPRequest{
					Method:        "GET",
					Protocol:      "HTTP/1.1",
					Host:          "example.com",
					URIPath:       "/api/test",
					Headers:       headers,
					ContentLength: 0,
				},
			},
		},
	}

	protoEvent := ConvertToProto(&e)

	require.NotNil(t, protoEvent.Data)
	assert.Len(t, protoEvent.Data, 1)

	assert.Equal(t, "http_request", protoEvent.Data[0].Name)
	httpReq := protoEvent.Data[0].GetHttpRequest()
	require.NotNil(t, httpReq)
	assert.Equal(t, "GET", httpReq.Method)
	assert.Equal(t, "HTTP/1.1", httpReq.Protocol)
	assert.Equal(t, "example.com", httpReq.Host)
	assert.Equal(t, "/api/test", httpReq.UriPath)
	assert.NotEmpty(t, httpReq.Headers)
}

func TestConvertToProto_EventData_HookedSyscalls(t *testing.T) {
	t.Parallel()

	// Use a non-syscall event ID
	e := trace.Event{
		EventID:   2021,
		EventName: "hooked_syscall",
		Args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{Name: "hooked_syscalls"},
				Value: []trace.HookedSymbolData{
					{SymbolName: "sys_read", ModuleOwner: "kernel"},
					{SymbolName: "sys_write", ModuleOwner: "rootkit"},
				},
			},
		},
	}

	protoEvent := ConvertToProto(&e)

	require.NotNil(t, protoEvent.Data)
	assert.Len(t, protoEvent.Data, 1)

	assert.Equal(t, "hooked_syscalls", protoEvent.Data[0].Name)
	hooked := protoEvent.Data[0].GetHookedSyscalls()
	require.NotNil(t, hooked)
	require.Len(t, hooked.Value, 2)
	assert.Equal(t, "sys_read", hooked.Value[0].SymbolName)
	assert.Equal(t, "kernel", hooked.Value[0].ModuleOwner)
	assert.Equal(t, "sys_write", hooked.Value[1].SymbolName)
	assert.Equal(t, "rootkit", hooked.Value[1].ModuleOwner)
}

func TestConvertFromProto_BasicFields(t *testing.T) {
	t.Parallel()

	execveID, _ := Core.GetDefinitionIDByName("execve")
	protoEvent := &pb.Event{
		Id:   pb.EventId(execveID),
		Name: "execve",
		Workload: &pb.Workload{
			Process: &pb.Process{
				Pid:      wrapperspb.UInt32(1001),
				HostPid:  wrapperspb.UInt32(1001),
				UniqueId: wrapperspb.UInt32(12345),
				RealUser: &pb.User{
					Id: wrapperspb.UInt32(1000),
				},
				Thread: &pb.Thread{
					Name:     "test_process",
					Tid:      wrapperspb.UInt32(1001),
					HostTid:  wrapperspb.UInt32(1001),
					UniqueId: wrapperspb.UInt32(12345),
				},
				Executable: &pb.Executable{
					Path: "/usr/bin/test",
				},
			},
		},
	}

	traceEvent := ConvertFromProto(protoEvent)

	assert.NotNil(t, traceEvent)
	assert.Equal(t, "execve", traceEvent.EventName)
	assert.Equal(t, 1001, traceEvent.ProcessID)
	assert.Equal(t, "test_process", traceEvent.ProcessName)
	assert.Equal(t, "/usr/bin/test", traceEvent.Executable.Path)
	assert.Equal(t, uint32(12345), traceEvent.ProcessEntityId)
	assert.Equal(t, 1000, traceEvent.UserID)
}

func TestConvertFromProto_Container(t *testing.T) {
	t.Parallel()

	protoEvent := &pb.Event{
		Id:   1,
		Name: "test_event",
		Workload: &pb.Workload{
			Container: &pb.Container{
				Id:      "abc123",
				Name:    "test_container",
				Started: true,
				Image: &pb.ContainerImage{
					Name:        "ubuntu:22.04",
					RepoDigests: []string{"sha256:abcdef123456"},
				},
			},
		},
	}

	traceEvent := ConvertFromProto(protoEvent)

	assert.NotNil(t, traceEvent)
	assert.Equal(t, "abc123", traceEvent.ContainerID)
	assert.Equal(t, "abc123", traceEvent.Container.ID)
	assert.Equal(t, "test_container", traceEvent.Container.Name)
	assert.True(t, traceEvent.ContextFlags.ContainerStarted)
	assert.Equal(t, "ubuntu:22.04", traceEvent.Container.ImageName)
	assert.Equal(t, "sha256:abcdef123456", traceEvent.Container.ImageDigest)
}

func TestConvertFromProto_EventData(t *testing.T) {
	t.Parallel()

	protoEvent := &pb.Event{
		Id:   2018,
		Name: "container_create",
		Data: []*pb.EventValue{
			{Name: "str_val", Value: &pb.EventValue_Str{Str: "hello"}},
			{Name: "int32_val", Value: &pb.EventValue_Int32{Int32: 42}},
			{Name: "uint64_val", Value: &pb.EventValue_UInt64{UInt64: 1000}},
			{Name: "bool_val", Value: &pb.EventValue_Bool{Bool: true}},
		},
	}

	traceEvent := ConvertFromProto(protoEvent)

	assert.NotNil(t, traceEvent)
	require.Len(t, traceEvent.Args, 4)

	assert.Equal(t, "str_val", traceEvent.Args[0].Name)
	assert.Equal(t, "hello", traceEvent.Args[0].Value)

	assert.Equal(t, "int32_val", traceEvent.Args[1].Name)
	assert.Equal(t, int32(42), traceEvent.Args[1].Value)

	assert.Equal(t, "uint64_val", traceEvent.Args[2].Name)
	assert.Equal(t, uint64(1000), traceEvent.Args[2].Value)

	assert.Equal(t, "bool_val", traceEvent.Args[3].Name)
	assert.Equal(t, true, traceEvent.Args[3].Value)
}

func TestRoundTrip_ConversionPreservesData(t *testing.T) {
	t.Parallel()

	execveID, _ := Core.GetDefinitionIDByName("execve")
	original := trace.Event{
		EventID:         int(execveID),
		EventName:       "execve",
		Timestamp:       1234567890,
		ProcessID:       1001,
		ProcessName:     "test_process",
		ProcessEntityId: 12345,
		UserID:          1000,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "filename"}, Value: "/bin/ls"},
			{ArgMeta: trace.ArgMeta{Name: "argv"}, Value: []string{"/bin/ls", "-la"}},
			{ArgMeta: trace.ArgMeta{Name: "flags"}, Value: uint32(0x123)},
		},
	}
	original.Executable.Path = "/usr/bin/test"

	// Convert to proto
	protoEvent := ConvertToProto(&original)
	assert.NotNil(t, protoEvent)

	// Convert back to trace
	converted := ConvertFromProto(protoEvent)
	assert.NotNil(t, converted)

	// Verify key fields are preserved
	assert.Equal(t, original.EventName, converted.EventName)
	assert.Equal(t, original.ProcessID, converted.ProcessID)
	assert.Equal(t, original.ProcessName, converted.ProcessName)
	assert.Equal(t, original.ProcessEntityId, converted.ProcessEntityId)
	assert.Equal(t, original.UserID, converted.UserID)
	assert.Equal(t, original.Executable.Path, converted.Executable.Path)

	// Verify args are preserved
	require.Len(t, converted.Args, 3)
	assert.Equal(t, "filename", converted.Args[0].Name)
	assert.Equal(t, "/bin/ls", converted.Args[0].Value)
	assert.Equal(t, "argv", converted.Args[1].Name)
	assert.Equal(t, []string{"/bin/ls", "-la"}, converted.Args[1].Value)
	assert.Equal(t, "flags", converted.Args[2].Name)
	assert.Equal(t, uint32(0x123), converted.Args[2].Value)
}

func TestConvertToProto_ThreatMetadata(t *testing.T) {
	t.Parallel()

	// Test that ConvertToProto correctly uses legacy getThreat function
	e := trace.Event{
		EventID:   2018,
		EventName: "container_create",
		Metadata: &trace.Metadata{
			Description: "Malicious activity detected",
			Properties: map[string]interface{}{
				"Severity":      3,
				"Category":      "Defense Evasion",
				"external_id":   "T1055",
				"Technique":     "Process Injection",
				"signatureName": "TestDetector",
			},
		},
	}

	protoEvent := ConvertToProto(&e)

	require.NotNil(t, protoEvent.Threat)
	assert.Equal(t, "Malicious activity detected", protoEvent.Threat.Description)
	assert.Equal(t, pb.Severity_HIGH, protoEvent.Threat.Severity)
	assert.Equal(t, "TestDetector", protoEvent.Threat.Name)
	assert.Equal(t, "Defense Evasion", protoEvent.Threat.Mitre.Tactic.Name)
	assert.Equal(t, "T1055", protoEvent.Threat.Mitre.Technique.Id)
	assert.Equal(t, "Process Injection", protoEvent.Threat.Mitre.Technique.Name)
}

func TestConvertToProto_ThreatMetadata_NoSeverity(t *testing.T) {
	t.Parallel()

	// Test that ConvertToProto returns nil Threat when Severity is missing
	e := trace.Event{
		EventID:   2018,
		EventName: "container_create",
		Metadata: &trace.Metadata{
			Description: "Some description",
			Properties: map[string]interface{}{
				"Category": "Defense Evasion",
			},
		},
	}

	protoEvent := ConvertToProto(&e)

	assert.Nil(t, protoEvent.Threat, "Threat should be nil when Severity is missing")
}
