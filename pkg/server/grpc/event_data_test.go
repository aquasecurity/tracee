package grpc

import (
	"reflect"
	"testing"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

func Test_getEventData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		args        []trace.Argument
		expected    map[string]*pb.EventValue
		syscall     bool
		returnValue int
	}{
		{
			name: "strT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "runtime",
						Type: "const char*",
					},
					Value: "docker",
				},
			},
			expected: map[string]*pb.EventValue{
				"runtime": {
					Value: &pb.EventValue_Str{
						Str: wrapperspb.String("docker"),
					},
				},
			},
		},
		{
			name: "intT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "sockfd",
						Type: "int",
					},
					Value: int32(31),
				},
			},
			expected: map[string]*pb.EventValue{
				"sockfd": {
					Value: &pb.EventValue_Int32{
						Int32: wrapperspb.Int32(31),
					},
				},
			},
		},
		{
			name: "uintT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "ipc",
						Type: "u32",
					},
					Value: uint32(4026531839),
				},
			},
			expected: map[string]*pb.EventValue{
				"ipc": {
					Value: &pb.EventValue_UInt32{
						UInt32: wrapperspb.UInt32(4026531839),
					},
				},
			},
		},
		{
			name: "longT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "exit_code",
						Type: "long",
					},
					Value: int64(1000),
				},
			},
			expected: map[string]*pb.EventValue{
				"exit_code": {
					Value: &pb.EventValue_Int64{
						Int64: wrapperspb.Int64(1000),
					},
				},
			},
		},
		{
			name: "ulongT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "inode",
						Type: "unsigned long",
					},
					Value: uint64(55577157),
				},
			},
			expected: map[string]*pb.EventValue{
				"inode": {
					Value: &pb.EventValue_UInt64{
						UInt64: wrapperspb.UInt64(55577157),
					},
				},
			},
		},
		{
			name: "offT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "pos",
						Type: "off_t",
					},
					Value: uint64(2),
				},
			},
			expected: map[string]*pb.EventValue{
				"pos": {
					Value: &pb.EventValue_UInt64{
						UInt64: wrapperspb.UInt64(2),
					},
				},
			},
		},
		{
			name: "modeT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "mode",
						Type: "mode_t",
					},
					Value: uint32(1),
				},
			},
			expected: map[string]*pb.EventValue{
				"mode": {
					Value: &pb.EventValue_UInt32{
						UInt32: wrapperspb.UInt32(1),
					},
				},
			},
		},
		{
			name: "devT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "dev",
						Type: "dev_t",
					},
					Value: uint32(59),
				},
			},
			expected: map[string]*pb.EventValue{
				"dev": {
					Value: &pb.EventValue_UInt32{
						UInt32: wrapperspb.UInt32(59),
					},
				},
			},
		},
		{
			name: "sizeT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "count",
						Type: "size_t",
					},
					Value: uint64(8),
				},
			},
			expected: map[string]*pb.EventValue{
				"count": {
					Value: &pb.EventValue_UInt64{
						UInt64: wrapperspb.UInt64(8),
					},
				},
			},
		},
		{
			name: "strArrT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "argv",
						Type: "const char*const*",
					},
					Value: []string{"runc", "init"},
				},
			},
			expected: map[string]*pb.EventValue{
				"argv": {
					Value: &pb.EventValue_StrArray{
						StrArray: &pb.StringArrayValue{
							Value: []*wrappers.StringValue{
								{Value: "runc"},
								{Value: "init"},
							},
						},
					},
				},
			},
		},
		{
			name: "bytesT", // bytesT -> {{bytes bytes} [49]}
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "bytes",
						Type: "bytes",
					},
					Value: []byte{49},
				},
			},
			expected: map[string]*pb.EventValue{
				"bytes": {
					Value: &pb.EventValue_Bytes{
						Bytes: wrapperspb.Bytes([]byte{49}),
					},
				},
			},
		},
		{
			name: "argsArrT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "prog_helpers",
						Type: "const char**",
					},
					Value: []string{"map_delete_elem", "probe_read_kernel"},
				},
			},
			expected: map[string]*pb.EventValue{
				"prog_helpers": {
					Value: &pb.EventValue_StrArray{
						StrArray: &pb.StringArrayValue{
							Value: []*wrappers.StringValue{
								{Value: "map_delete_elem"},
								{Value: "probe_read_kernel"},
							},
						},
					},
				},
			},
		},
		{
			name: "u8",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "sa_handle_method",
						Type: "u8",
					},
					Value: uint8(8),
				},
			},
			expected: map[string]*pb.EventValue{
				"sa_handle_method": {
					Value: &pb.EventValue_UInt32{
						UInt32: wrapperspb.UInt32(8),
					},
				},
			},
		},
		{
			name: "u16T",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "inode_mode",
						Type: "umode_t",
					},
					Value: uint16(1818),
				},
			},
			expected: map[string]*pb.EventValue{
				"inode_mode": {
					Value: &pb.EventValue_UInt32{
						UInt32: wrapperspb.UInt32(1818),
					},
				},
			},
		},
		{
			name: "boolT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "process_group_exit",
						Type: "bool",
					},
					Value: true,
				},
			},
			expected: map[string]*pb.EventValue{
				"process_group_exit": {
					Value: &pb.EventValue_Bool{
						Bool: wrapperspb.Bool(true),
					},
				},
			},
		},
		{
			name: "pointerT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "sa_handler",
						Type: "void*",
					},
					Value: uintptr(0xFFFFFFFFFFFFFFFF),
				},
			},
			expected: map[string]*pb.EventValue{
				"sa_handler": {
					Value: &pb.EventValue_UInt64{
						UInt64: wrapperspb.UInt64(18446744073709551615),
					},
				},
			},
		},
		{
			name: "intArr2T",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "pipefd",
						Type: "int[2]",
					},
					Value: [2]int32{3, 4},
				},
			},
			expected: map[string]*pb.EventValue{
				"pipefd": {
					Value: &pb.EventValue_Int32Array{
						Int32Array: &pb.Int32ArrayValue{
							Value: []*wrappers.Int32Value{
								wrapperspb.Int32(3),
								wrapperspb.Int32(4),
							},
						},
					},
				},
			},
		},
		{
			name: "uint64ArrT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "syscalls_addresses",
						Type: "unsigned long[]",
					},
					Value: []uint64{18446744073709551615, 18446744073709551615},
				},
			},
			expected: map[string]*pb.EventValue{
				"syscalls_addresses": {
					Value: &pb.EventValue_UInt64Array{
						UInt64Array: &pb.UInt64ArrayValue{
							Value: []*wrappers.UInt64Value{
								wrapperspb.UInt64(18446744073709551615),
								wrapperspb.UInt64(18446744073709551615),
							},
						},
					},
				},
			},
		},
		{
			name: "timespecT", // timespecT -> {{req const struct timespec*} 2e-05}
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "req",
						Type: "const struct timespec*",
					},
					Value: float64(2e-05),
				},
			},
			expected: map[string]*pb.EventValue{
				"req": {
					Value: &pb.EventValue_Timespec{
						Timespec: &pb.TimespecValue{
							Value: wrapperspb.Double(2e-05),
						},
					},
				},
			},
		},
		{
			name: "sockAddrT - AF_INET",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "sockAddr0",
						Type: "struct sockaddr*",
					},
					Value: map[string]string(map[string]string{"sa_family": "AF_INET", "sin_addr": "255.255.255.255", "sin_port": "65535"}),
				},
			},
			expected: map[string]*pb.EventValue{
				"sockAddr0": {
					Value: &pb.EventValue_Sockaddr{
						Sockaddr: &pb.SockAddrValue{
							SaFamily: pb.SaFamilyT_AF_INET,
							SinAddr:  "255.255.255.255",
							SinPort:  uint32(65535),
						},
					},
				},
			},
		},
		{
			name: "sockAddrT - AF_UNIX",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "sockAddr0",
						Type: "struct sockaddr*",
					},
					Value: map[string]string{"sa_family": "AF_UNIX", "sun_path": "/tmp/socket"},
				},
			},
			expected: map[string]*pb.EventValue{
				"sockAddr0": {
					Value: &pb.EventValue_Sockaddr{
						Sockaddr: &pb.SockAddrValue{
							SaFamily: pb.SaFamilyT_AF_UNIX,
							SunPath:  "/tmp/socket",
						},
					},
				},
			},
		},
		{
			name: "credT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "new_cred",
						Type: "slim_cred_t",
					},
					Value: trace.SlimCred{
						Uid:            1,
						Gid:            2,
						Suid:           3,
						Sgid:           4,
						Euid:           5,
						Egid:           6,
						Fsuid:          7,
						Fsgid:          8,
						UserNamespace:  4026531837,
						SecureBits:     0,
						CapInheritable: 0,
						CapPermitted:   12,
						CapEffective:   0,
						CapBounding:    0,
						CapAmbient:     0,
					},
				},
			},
			expected: map[string]*pb.EventValue{
				"new_cred": {
					Value: &pb.EventValue_Cred{
						Cred: &pb.CredValue{
							Uid:            wrapperspb.UInt32(1),
							Gid:            wrapperspb.UInt32(2),
							Suid:           wrapperspb.UInt32(3),
							Sgid:           wrapperspb.UInt32(4),
							Euid:           wrapperspb.UInt32(5),
							Egid:           wrapperspb.UInt32(6),
							Fsuid:          wrapperspb.UInt32(7),
							Fsgid:          wrapperspb.UInt32(8),
							UserNamespace:  wrapperspb.UInt32(4026531837),
							SecureBits:     wrapperspb.UInt32(0),
							CapInheritable: nil,
							CapPermitted: []pb.Capability{
								pb.Capability_CAP_DAC_READ_SEARCH,
								pb.Capability_CAP_FOWNER,
							},
							CapEffective: nil,
							CapBounding:  nil,
							CapAmbient:   nil,
						},
					},
				},
			},
		},
		{
			name: "multipe arguments",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "inode_mode",
						Type: "umode_t",
					},
					Value: uint16(1818),
				},
				{
					ArgMeta: trace.ArgMeta{
						Name: "process_group_exit",
						Type: "bool",
					},
					Value: true,
				},
				{
					ArgMeta: trace.ArgMeta{
						Name: "sa_handler",
						Type: "void*",
					},
					Value: uintptr(0xFFFFFFFFFFFFFFFF),
				},
			},
			expected: map[string]*pb.EventValue{
				"inode_mode": {
					Value: &pb.EventValue_UInt32{
						UInt32: wrapperspb.UInt32(1818),
					},
				},
				"process_group_exit": {
					Value: &pb.EventValue_Bool{
						Bool: wrapperspb.Bool(true),
					},
				},
				"sa_handler": {
					Value: &pb.EventValue_UInt64{
						UInt64: wrapperspb.UInt64(18446744073709551615),
					},
				},
			},
		},
		{
			name:        "syscall",
			syscall:     true,
			returnValue: -1,
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "inode_mode",
						Type: "umode_t",
					},
					Value: uint16(1818),
				},
			},
			expected: map[string]*pb.EventValue{
				"args": {
					Value: &pb.EventValue_Args{
						Args: &pb.ArgsValue{
							Value: []*pb.EventValue{
								{
									Value: &pb.EventValue_UInt32{
										UInt32: wrapperspb.UInt32(1818),
									},
								},
							},
						},
					},
				},
				"returnValue": {
					Value: &pb.EventValue_Int64{
						Int64: wrapperspb.Int64(-1),
					},
				},
			},
		},
		{
			name:        "syscall - multiple arguments",
			syscall:     true,
			returnValue: 1,
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "inode_mode",
						Type: "umode_t",
					},
					Value: uint16(1818),
				},
				{
					ArgMeta: trace.ArgMeta{
						Name: "ipc",
						Type: "u32",
					},
					Value: uint32(4026531839),
				},
			},
			expected: map[string]*pb.EventValue{
				"args": {
					Value: &pb.EventValue_Args{
						Args: &pb.ArgsValue{
							Value: []*pb.EventValue{
								{
									Value: &pb.EventValue_UInt32{
										UInt32: wrapperspb.UInt32(1818),
									},
								},
								{
									Value: &pb.EventValue_UInt32{
										UInt32: wrapperspb.UInt32(4026531839),
									},
								},
							},
						},
					},
				},
				"returnValue": {
					Value: &pb.EventValue_Int64{
						Int64: wrapperspb.Int64(1),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			id := int(events.CommitCreds)
			if tt.syscall {
				id = int(events.Ptrace)
			}

			eventData, err := getEventData(trace.Event{EventID: id, Args: tt.args, ReturnValue: tt.returnValue})
			assert.NoError(t, err)

			assert.Equal(t, len(tt.expected), len(eventData))

			for name, expected := range tt.expected {
				actual, ok := eventData[name]
				assert.True(t, ok)
				assert.NotNil(t, actual)

				if !ok || actual == nil {
					continue
				}

				assert.Equal(t, reflect.TypeOf(expected.Value), reflect.TypeOf(actual.Value))

				switch actual.Value.(type) {
				case *pb.EventValue_Int32:
					assert.Equal(t, expected.GetInt32().GetValue(), actual.GetInt32().GetValue())
				case *pb.EventValue_Str:
					assert.Equal(t, expected.GetStr().GetValue(), actual.GetStr().GetValue())
				case *pb.EventValue_UInt32:
					assert.Equal(t, expected.GetUInt32().GetValue(), actual.GetUInt32().GetValue())
				case *pb.EventValue_Int64:
					assert.Equal(t, expected.GetInt64().GetValue(), actual.GetInt64().GetValue())
				case *pb.EventValue_UInt64:
					assert.Equal(t, expected.GetUInt64().GetValue(), actual.GetUInt64().GetValue())
				case *pb.EventValue_StrArray:
					assert.Equal(t, expected.GetStrArray().GetValue(), actual.GetStrArray().GetValue())
				case *pb.EventValue_Bytes:
					assert.Equal(t, expected.GetBytes().GetValue(), actual.GetBytes().GetValue())
				case *pb.EventValue_Bool:
					assert.Equal(t, expected.GetBool().GetValue(), actual.GetBool().GetValue())
				case *pb.EventValue_Int32Array:
					assert.Equal(t, expected.GetInt32Array().GetValue(), actual.GetInt32Array().GetValue())
				case *pb.EventValue_UInt64Array:
					assert.Equal(t, expected.GetUInt64Array().GetValue(), actual.GetUInt64Array().GetValue())
				case *pb.EventValue_Timespec:
					assert.Equal(t, expected.GetTimespec().GetValue(), actual.GetTimespec().GetValue())
				case *pb.EventValue_Sockaddr:
					assert.Equal(t, expected.GetSockaddr().GetSaFamily(), actual.GetSockaddr().GetSaFamily())
					assert.Equal(t, expected.GetSockaddr().GetSunPath(), actual.GetSockaddr().GetSunPath())
					assert.Equal(t, expected.GetSockaddr().GetSinAddr(), actual.GetSockaddr().GetSinAddr())
					assert.Equal(t, expected.GetSockaddr().GetSinPort(), actual.GetSockaddr().GetSinPort())
				case *pb.EventValue_Cred:
					assert.Equal(t, expected.GetCred().GetUid().GetValue(), actual.GetCred().GetUid().GetValue())
					assert.Equal(t, expected.GetCred().GetGid().GetValue(), actual.GetCred().GetGid().GetValue())
					assert.Equal(t, expected.GetCred().GetSuid().GetValue(), actual.GetCred().GetSuid().GetValue())
					assert.Equal(t, expected.GetCred().GetEuid().GetValue(), actual.GetCred().GetEuid().GetValue())
					assert.Equal(t, expected.GetCred().GetEgid().GetValue(), actual.GetCred().GetEgid().GetValue())
					assert.Equal(t, expected.GetCred().GetFsuid().GetValue(), actual.GetCred().GetFsuid().GetValue())
					assert.Equal(t, expected.GetCred().GetFsgid().GetValue(), actual.GetCred().GetFsgid().GetValue())
					assert.Equal(t, expected.GetCred().GetUserNamespace().GetValue(), actual.GetCred().GetUserNamespace().GetValue())
					assert.Equal(t, expected.GetCred().GetSecureBits().GetValue(), actual.GetCred().GetSecureBits().GetValue())
					assert.Equal(t, expected.GetCred().GetCapInheritable(), actual.GetCred().GetCapInheritable())
					assert.Equal(t, expected.GetCred().GetCapPermitted(), actual.GetCred().GetCapPermitted())
					assert.Equal(t, expected.GetCred().GetCapEffective(), actual.GetCred().GetCapEffective())
					assert.Equal(t, expected.GetCred().GetCapBounding(), actual.GetCred().GetCapBounding())
					assert.Equal(t, expected.GetCred().GetCapAmbient(), actual.GetCred().GetCapAmbient())
				case *pb.EventValue_Args:
					for i, arg := range expected.GetArgs().GetValue() {
						value1 := arg.GetValue().(*pb.EventValue_UInt32)
						value2 := actual.GetArgs().GetValue()[i].GetValue().(*pb.EventValue_UInt32)
						assert.Equal(t, value1.UInt32.GetValue(), value2.UInt32.GetValue())
					}
				default:
					t.Errorf("unexpected type %T", actual.Value)
				}
			}
		})
	}
}

func TestEventTrigger(t *testing.T) {
	event := trace.Event{
		EventID: 6001,
		Args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{
					Name: "arg1",
					Type: "const char *",
				},
				Value: "value1",
			},
			{
				ArgMeta: trace.ArgMeta{
					Name: "triggeredBy",
					Type: "unknown",
				},
				Value: map[string]interface{}{
					"id":   int(events.Ptrace),
					"name": "ptrace",
					"args": []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "arg1",
								Type: "const char *",
							},
							Value: "arg value",
						},
					},
					"returnValue": 10,
				},
			},
		},
	}

	eventData, err := getEventData(event)
	assert.NoError(t, err)

	expected := map[string]*pb.EventValue{
		"arg1": {
			Value: &pb.EventValue_Str{
				Str: wrapperspb.String("value1"),
			},
		},
		"triggeredBy": {
			Value: &pb.EventValue_TriggeredBy{
				TriggeredBy: &pb.TriggeredBy{
					Id:   101,
					Name: "ptrace",
					Data: map[string]*pb.EventValue{
						"args": {
							Value: &pb.EventValue_Args{
								Args: &pb.ArgsValue{
									Value: []*pb.EventValue{
										{
											Value: &pb.EventValue_Str{
												Str: wrapperspb.String("arg value"),
											},
										},
									},
								},
							},
						},
						"returnValue": {
							Value: &pb.EventValue_Int64{
								Int64: wrapperspb.Int64(10),
							},
						},
					},
				},
			},
		},
	}

	assert.Equal(t, len(expected), len(eventData))

	expectedTriggerEvent := expected["triggeredBy"].GetTriggeredBy()
	assert.NotNil(t, expectedTriggerEvent)

	actualTriggerEvent := eventData["triggeredBy"].GetTriggeredBy()
	assert.NotNil(t, actualTriggerEvent)

	assert.Equal(t, expectedTriggerEvent.Id, actualTriggerEvent.Id)
	assert.Equal(t, expectedTriggerEvent.Name, actualTriggerEvent.Name)

	assert.Equal(t, len(expectedTriggerEvent.Data), len(actualTriggerEvent.Data))
	assert.Equal(t, expectedTriggerEvent.Data, actualTriggerEvent.Data)
}
