package grpc

import (
	"reflect"
	"testing"

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
		expected    []*pb.EventValue
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
			expected: []*pb.EventValue{
				{
					Name: "runtime",
					Value: &pb.EventValue_Str{
						Str: "docker",
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
			expected: []*pb.EventValue{
				{
					Name: "sockfd",
					Value: &pb.EventValue_Int32{
						Int32: 31,
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
			expected: []*pb.EventValue{
				{
					Name: "ipc",
					Value: &pb.EventValue_UInt32{
						UInt32: 4026531839,
					},
				},
			},
		},
		{
			name: "longT",
			args: []trace.Argument{
				{
					ArgMeta: trace.ArgMeta{
						Name: "newmask",
						Type: "long",
					},
					Value: int64(1000),
				},
			},
			expected: []*pb.EventValue{
				{
					Name: "newmask",
					Value: &pb.EventValue_Int64{
						Int64: 1000,
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
			expected: []*pb.EventValue{
				{
					Name: "inode",
					Value: &pb.EventValue_UInt64{
						UInt64: 55577157,
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
			expected: []*pb.EventValue{
				{
					Name: "pos",
					Value: &pb.EventValue_UInt64{
						UInt64: 2,
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
			expected: []*pb.EventValue{
				{
					Name: "mode",
					Value: &pb.EventValue_UInt32{
						UInt32: 1,
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
			expected: []*pb.EventValue{
				{
					Name: "dev",
					Value: &pb.EventValue_UInt32{
						UInt32: 59,
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
			expected: []*pb.EventValue{
				{
					Name: "count",
					Value: &pb.EventValue_UInt64{
						UInt64: 8,
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
			expected: []*pb.EventValue{
				{
					Name: "argv",
					Value: &pb.EventValue_StrArray{
						StrArray: &pb.StringArray{
							Value: []string{
								"runc",
								"init",
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
			expected: []*pb.EventValue{
				{
					Name: "bytes",
					Value: &pb.EventValue_Bytes{
						Bytes: []byte{49},
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
			expected: []*pb.EventValue{
				{
					Name: "prog_helpers",
					Value: &pb.EventValue_StrArray{
						StrArray: &pb.StringArray{
							Value: []string{
								"map_delete_elem",
								"probe_read_kernel",
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
			expected: []*pb.EventValue{
				{
					Name: "sa_handle_method",
					Value: &pb.EventValue_UInt32{
						UInt32: 8,
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
			expected: []*pb.EventValue{
				{
					Name: "inode_mode",
					Value: &pb.EventValue_UInt32{
						UInt32: 1818,
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
			expected: []*pb.EventValue{
				{
					Name: "process_group_exit",
					Value: &pb.EventValue_Bool{
						Bool: true,
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
			expected: []*pb.EventValue{
				{
					Name: "sa_handler",
					Value: &pb.EventValue_UInt64{
						UInt64: 18446744073709551615,
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
			expected: []*pb.EventValue{
				{
					Name: "pipefd",
					Value: &pb.EventValue_Int32Array{
						Int32Array: &pb.Int32Array{
							Value: []int32{
								3,
								4,
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
			expected: []*pb.EventValue{
				{
					Name: "syscalls_addresses",
					Value: &pb.EventValue_UInt64Array{
						UInt64Array: &pb.UInt64Array{
							Value: []uint64{
								18446744073709551615,
								18446744073709551615,
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
			expected: []*pb.EventValue{
				{
					Name: "req",
					Value: &pb.EventValue_Timespec{
						Timespec: &pb.Timespec{
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
			expected: []*pb.EventValue{
				{
					Name: "sockAddr0",
					Value: &pb.EventValue_Sockaddr{
						Sockaddr: &pb.SockAddr{
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
			expected: []*pb.EventValue{
				{
					Name: "sockAddr0",
					Value: &pb.EventValue_Sockaddr{
						Sockaddr: &pb.SockAddr{
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
			expected: []*pb.EventValue{
				{
					Name: "new_cred",
					Value: &pb.EventValue_Credentials{
						Credentials: &pb.Credentials{
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
			expected: []*pb.EventValue{
				{
					Name: "inode_mode",
					Value: &pb.EventValue_UInt32{
						UInt32: 1818,
					},
				},
				{
					Name: "process_group_exit",
					Value: &pb.EventValue_Bool{
						Bool: true,
					},
				},
				{
					Name: "sa_handler",
					Value: &pb.EventValue_UInt64{
						UInt64: 18446744073709551615,
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
			expected: []*pb.EventValue{
				{
					Name: "inode_mode",
					Value: &pb.EventValue_UInt32{
						UInt32: 1818,
					},
				},
				{
					Name: "returnValue",
					Value: &pb.EventValue_Int64{
						Int64: -1,
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
			expected: []*pb.EventValue{
				{
					Name: "inode_mode",
					Value: &pb.EventValue_UInt32{
						UInt32: 1818,
					},
				},
				{
					Name: "ipc",
					Value: &pb.EventValue_UInt32{
						UInt32: 4026531839,
					},
				},
				{
					Name: "returnValue",
					Value: &pb.EventValue_Int64{
						Int64: 1,
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

			for index, expected := range tt.expected {
				actual := eventData[index]
				assert.NotNil(t, actual)

				assert.Equal(t, reflect.TypeOf(expected.Value), reflect.TypeOf(actual.Value))

				switch actual.Value.(type) {
				case *pb.EventValue_Int32:
					assert.Equal(t, expected.GetInt32(), actual.GetInt32())
				case *pb.EventValue_Str:
					assert.Equal(t, expected.GetStr(), actual.GetStr())
				case *pb.EventValue_UInt32:
					assert.Equal(t, expected.GetUInt32(), actual.GetUInt32())
				case *pb.EventValue_Int64:
					assert.Equal(t, expected.GetInt64(), actual.GetInt64())
				case *pb.EventValue_UInt64:
					assert.Equal(t, expected.GetUInt64(), actual.GetUInt64())
				case *pb.EventValue_StrArray:
					assert.Equal(t, expected.GetStrArray(), actual.GetStrArray())
				case *pb.EventValue_Bytes:
					assert.Equal(t, expected.GetBytes(), actual.GetBytes())
				case *pb.EventValue_Bool:
					assert.Equal(t, expected.GetBool(), actual.GetBool())
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
				case *pb.EventValue_Credentials:
					assert.Equal(t, expected.GetCredentials().GetUid().GetValue(), actual.GetCredentials().GetUid().GetValue())
					assert.Equal(t, expected.GetCredentials().GetGid().GetValue(), actual.GetCredentials().GetGid().GetValue())
					assert.Equal(t, expected.GetCredentials().GetSuid().GetValue(), actual.GetCredentials().GetSuid().GetValue())
					assert.Equal(t, expected.GetCredentials().GetEuid().GetValue(), actual.GetCredentials().GetEuid().GetValue())
					assert.Equal(t, expected.GetCredentials().GetEgid().GetValue(), actual.GetCredentials().GetEgid().GetValue())
					assert.Equal(t, expected.GetCredentials().GetFsuid().GetValue(), actual.GetCredentials().GetFsuid().GetValue())
					assert.Equal(t, expected.GetCredentials().GetFsgid().GetValue(), actual.GetCredentials().GetFsgid().GetValue())
					assert.Equal(t, expected.GetCredentials().GetUserNamespace().GetValue(), actual.GetCredentials().GetUserNamespace().GetValue())
					assert.Equal(t, expected.GetCredentials().GetSecureBits().GetValue(), actual.GetCredentials().GetSecureBits().GetValue())
					assert.Equal(t, expected.GetCredentials().GetCapInheritable(), actual.GetCredentials().GetCapInheritable())
					assert.Equal(t, expected.GetCredentials().GetCapPermitted(), actual.GetCredentials().GetCapPermitted())
					assert.Equal(t, expected.GetCredentials().GetCapEffective(), actual.GetCredentials().GetCapEffective())
					assert.Equal(t, expected.GetCredentials().GetCapBounding(), actual.GetCredentials().GetCapBounding())
					assert.Equal(t, expected.GetCredentials().GetCapAmbient(), actual.GetCredentials().GetCapAmbient())
				default:
					t.Errorf("unexpected type %T", actual.Value)
				}
			}
		})
	}
}

func TestEventTrigger(t *testing.T) {
	event := trace.Event{
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

	expectedTriggerEvent, err := getTriggerBy(event.Args)
	assert.NoError(t, err)

	actualTriggerId, ok := event.Args[1].Value.(map[string]interface{})["id"].(int)
	assert.True(t, ok)
	actualTriggerName, ok := event.Args[1].Value.(map[string]interface{})["name"].(string)
	assert.True(t, ok)
	actualTriggerArgs, ok := event.Args[1].Value.(map[string]interface{})["args"].([]trace.Argument)
	assert.True(t, ok)
	actualTriggerArg0Str, ok := actualTriggerArgs[0].Value.(string)
	assert.True(t, ok)
	actualArg1Name := "returnValue"
	actualArg1Value, ok := event.Args[1].Value.(map[string]interface{})["returnValue"].(int)
	assert.True(t, ok)

	assert.Equal(t, expectedTriggerEvent.Id, uint32(actualTriggerId))
	assert.Equal(t, expectedTriggerEvent.Name, actualTriggerName)

	expectedArg0Name := expectedTriggerEvent.Data[0].GetName()
	expectedArg0StrValue := expectedTriggerEvent.Data[0].GetValue().(*pb.EventValue_Str).Str
	assert.Equal(t, expectedArg0Name, actualTriggerArgs[0].ArgMeta.Name)
	assert.Equal(t, expectedArg0StrValue, actualTriggerArg0Str)

	expectedArg1Name := expectedTriggerEvent.Data[1].GetName()
	expectedArg1Value := expectedTriggerEvent.Data[1].GetValue().(*pb.EventValue_Int64).Int64
	assert.Equal(t, expectedArg1Name, actualArg1Name)
	assert.Equal(t, expectedArg1Value, int64(actualArg1Value))
}
