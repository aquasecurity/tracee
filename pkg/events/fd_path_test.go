package events

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

// Check the actual C selection table against the Go definitions. Keeping a
// second syscall allowlist in Go would allow the original mismatch to return.
func TestFDPathKernelArgumentContract(t *testing.T) {
	source, err := os.ReadFile("../ebpf/c/common/arch.h")
	require.NoError(t, err)
	_, selector, found := strings.Cut(string(source), "statfunc int get_syscall_fd_arg_index(uint syscall_id)")
	require.True(t, found)
	tokens := regexp.MustCompile(`case SYSCALL_([A-Z0-9_]+):|return ([0-5]);`).FindAllStringSubmatch(selector, -1)
	var pending []string
	checked := 0
	for _, token := range tokens {
		if token[1] != "" {
			pending = append(pending, strings.ToLower(token[1]))
			continue
		}
		index, err := strconv.Atoi(token[2])
		require.NoError(t, err)
		for _, name := range pending {
			t.Run(name, func(t *testing.T) {
				definition := Core.GetDefinitionByName(name)
				require.False(t, definition.NotValid())
				fields := definition.GetFields()
				require.Less(t, index, len(fields))
				selected := fields[index]
				target := &pb.EventValue{Name: selected.Name}
				switch selected.Type {
				case "int32":
					target.Value = &pb.EventValue_Int32{Int32: 7}
				case "uint32":
					target.Value = &pb.EventValue_UInt32{UInt32: 7}
				case "trace.Pointer":
					target.Value = &pb.EventValue_Pointer{Pointer: 7}
				default:
					t.Fatalf("unsupported selected argument type %s", selected.Type)
				}
				other := "fd"
				if selected.Name == other {
					other = "unselected_fd"
				}
				fieldsOut := []*pb.EventValue{{Name: other, Value: &pb.EventValue_Int32{Int32: 99}}, target}
				snapshot := FDPath{ArgIndex: uint8(index), ArgName: selected.Name, Status: FDPathResolved, Path: "/tmp/selected"}
				require.NoError(t, ParseDataFieldsFDs(fieldsOut, snapshot))
				require.Equal(t, "7=/tmp/selected", target.GetStr())
				require.Equal(t, int32(99), fieldsOut[0].GetInt32())
				require.NoError(t, ParseDataFields(fieldsOut, int(definition.GetID())))
				require.Equal(t, "7=/tmp/selected", target.GetStr())
			})
			checked++
		}
		pending = nil
	}
	require.Empty(t, pending)
	require.GreaterOrEqual(t, checked, 96, "the existing producer coverage must not shrink")
}

func TestFDPathDirectorySentinels(t *testing.T) {
	for _, name := range []string{"dirfd", "dfd", "newdirfd"} {
		field := &pb.EventValue{Name: name, Value: &pb.EventValue_Int32{Int32: -100}}
		require.NoError(t, ParseDataFieldsFDs([]*pb.EventValue{field}, FDPath{ArgName: name, Status: FDPathUnavailable}))
		require.Equal(t, "AT_FDCWD", field.GetStr())
	}
	field := &pb.EventValue{Name: "fd", Value: &pb.EventValue_Int32{Int32: -100}}
	require.NoError(t, ParseDataFieldsFDs([]*pb.EventValue{field}, FDPath{ArgName: "fd", Status: FDPathUnavailable}))
	require.Equal(t, int32(-100), field.GetInt32())
}
