package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

func TestGetFieldValue(t *testing.T) {
	t.Parallel()

	data := []*pb.EventValue{
		{
			Name:  "arg1",
			Value: &pb.EventValue_Int32{Int32: 42},
		},
		{
			Name:  "arg2",
			Value: &pb.EventValue_Str{Str: "test"},
		},
	}

	t.Run("Found", func(t *testing.T) {
		field := GetFieldValue(data, "arg1")
		require.NotNil(t, field)
		assert.Equal(t, "arg1", field.Name)
		assert.Equal(t, int32(42), field.Value.(*pb.EventValue_Int32).Int32)
	})

	t.Run("Not found", func(t *testing.T) {
		field := GetFieldValue(data, "nonexistent")
		assert.Nil(t, field)
	})
}

func TestParseDataFields(t *testing.T) {
	t.Parallel()

	t.Run("Parse SysEnter syscall", func(t *testing.T) {
		t.Parallel()

		data := []*pb.EventValue{
			{
				Name:  "syscall",
				Value: &pb.EventValue_Int32{Int32: int32(Openat)},
			},
		}

		err := ParseDataFields(data, int(SysEnter))
		require.NoError(t, err)

		syscallField := GetFieldValue(data, "syscall")
		require.NotNil(t, syscallField)

		// Should be converted to string with syscall name
		strVal, ok := syscallField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "syscall should be converted to string")
		assert.Equal(t, "openat", strVal.Str)
	})

	t.Run("Parse mmap prot", func(t *testing.T) {
		t.Parallel()

		// PROT_READ | PROT_WRITE = 0x1 | 0x2 = 0x3
		data := []*pb.EventValue{
			{
				Name:  "prot",
				Value: &pb.EventValue_Int32{Int32: 0x3},
			},
		}

		err := ParseDataFields(data, int(Mmap))
		require.NoError(t, err)

		protField := GetFieldValue(data, "prot")
		require.NotNil(t, protField)

		// Should be converted to string
		strVal, ok := protField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "prot should be converted to string")
		assert.Contains(t, strVal.Str, "PROT_")
	})

	t.Run("Parse mmap flags", func(t *testing.T) {
		t.Parallel()

		// MAP_PRIVATE | MAP_ANONYMOUS = 0x2 | 0x20 = 0x22
		data := []*pb.EventValue{
			{
				Name:  "flags",
				Value: &pb.EventValue_Int32{Int32: 0x22},
			},
		}

		err := ParseDataFields(data, int(Mmap))
		require.NoError(t, err)

		flagsField := GetFieldValue(data, "flags")
		require.NotNil(t, flagsField)

		// Should be converted to string
		strVal, ok := flagsField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "mmap flags should be converted to string")
		assert.Contains(t, strVal.Str, "MAP_")
	})

	t.Run("Parse setns nstype", func(t *testing.T) {
		t.Parallel()

		// CLONE_NEWNET = 0x40000000
		data := []*pb.EventValue{
			{
				Name:  "nstype",
				Value: &pb.EventValue_Int32{Int32: 0x40000000},
			},
		}

		err := ParseDataFields(data, int(Setns))
		require.NoError(t, err)

		nstypeField := GetFieldValue(data, "nstype")
		require.NotNil(t, nstypeField)

		// Should be converted to string
		strVal, ok := nstypeField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "nstype should be converted to string")
		assert.Equal(t, "CLONE_NEWNET", strVal.Str)
	})

	t.Run("Parse setns nstype zero", func(t *testing.T) {
		t.Parallel()

		// 0 = any namespace type
		data := []*pb.EventValue{
			{
				Name:  "nstype",
				Value: &pb.EventValue_Int32{Int32: 0},
			},
		}

		err := ParseDataFields(data, int(Setns))
		require.NoError(t, err)

		nstypeField := GetFieldValue(data, "nstype")
		require.NotNil(t, nstypeField)

		// Should be converted to string "0"
		strVal, ok := nstypeField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "nstype should be converted to string")
		assert.Equal(t, "0", strVal.Str)
	})

	t.Run("Parse setns nstype multiple", func(t *testing.T) {
		t.Parallel()

		// CLONE_NEWNS | CLONE_NEWNET = 0x20000 | 0x40000000
		data := []*pb.EventValue{
			{
				Name:  "nstype",
				Value: &pb.EventValue_Int32{Int32: 0x40020000},
			},
		}

		err := ParseDataFields(data, int(Setns))
		require.NoError(t, err)

		nstypeField := GetFieldValue(data, "nstype")
		require.NotNil(t, nstypeField)

		// Should be converted to string with both types
		strVal, ok := nstypeField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "nstype should be converted to string")
		assert.Contains(t, strVal.Str, "CLONE_NEW")
	})

	t.Run("Parse socket domain", func(t *testing.T) {
		t.Parallel()

		// AF_INET = 2
		data := []*pb.EventValue{
			{
				Name:  "domain",
				Value: &pb.EventValue_Int32{Int32: 2},
			},
		}

		err := ParseDataFields(data, int(Socket))
		require.NoError(t, err)

		domainField := GetFieldValue(data, "domain")
		require.NotNil(t, domainField)

		// Should be converted to string
		strVal, ok := domainField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "domain should be converted to string")
		assert.Equal(t, "AF_INET", strVal.Str)
	})

	t.Run("Parse socket type", func(t *testing.T) {
		t.Parallel()

		// SOCK_STREAM = 1
		data := []*pb.EventValue{
			{
				Name:  "type",
				Value: &pb.EventValue_Int32{Int32: 1},
			},
		}

		err := ParseDataFields(data, int(Socket))
		require.NoError(t, err)

		typeField := GetFieldValue(data, "type")
		require.NotNil(t, typeField)

		// Should be converted to string
		strVal, ok := typeField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "type should be converted to string")
		assert.Contains(t, strVal.Str, "SOCK_")
	})

	t.Run("Parse capability", func(t *testing.T) {
		t.Parallel()

		// CAP_SYS_ADMIN = 21
		data := []*pb.EventValue{
			{
				Name:  "cap",
				Value: &pb.EventValue_Int32{Int32: 21},
			},
		}

		err := ParseDataFields(data, int(CapCapable))
		require.NoError(t, err)

		capField := GetFieldValue(data, "cap")
		require.NotNil(t, capField)

		// Should be converted to string
		strVal, ok := capField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "cap should be converted to string")
		assert.Equal(t, "CAP_SYS_ADMIN", strVal.Str)
	})

	t.Run("Parse open flags", func(t *testing.T) {
		t.Parallel()

		// O_RDWR | O_CREAT = 0x2 | 0x40 = 0x42
		data := []*pb.EventValue{
			{
				Name:  "flags",
				Value: &pb.EventValue_Int32{Int32: 0x42},
			},
		}

		err := ParseDataFields(data, int(Open))
		require.NoError(t, err)

		flagsEv := GetFieldValue(data, "flags")
		require.NotNil(t, flagsEv)

		// Should be converted to string
		strVal, ok := flagsEv.Value.(*pb.EventValue_Str)
		require.True(t, ok, "flags should be converted to string")
		assert.Contains(t, strVal.Str, "O_")
	})

	t.Run("Parse clone flags", func(t *testing.T) {
		t.Parallel()

		// CLONE_VM = 0x100
		data := []*pb.EventValue{
			{
				Name:  "flags",
				Value: &pb.EventValue_UInt64{UInt64: 0x100},
			},
		}

		err := ParseDataFields(data, int(Clone))
		require.NoError(t, err)

		flagsEv := GetFieldValue(data, "flags")
		require.NotNil(t, flagsEv)

		// Should be converted to string
		strVal, ok := flagsEv.Value.(*pb.EventValue_Str)
		require.True(t, ok, "flags should be converted to string")
		assert.Contains(t, strVal.Str, "CLONE_")
	})

	t.Run("Parse BPF command", func(t *testing.T) {
		t.Parallel()

		// BPF_PROG_LOAD = 5
		data := []*pb.EventValue{
			{
				Name:  "cmd",
				Value: &pb.EventValue_Int32{Int32: 5},
			},
		}

		err := ParseDataFields(data, int(Bpf))
		require.NoError(t, err)

		cmdField := GetFieldValue(data, "cmd")
		require.NotNil(t, cmdField)

		// Should be converted to string
		strVal, ok := cmdField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "cmd should be converted to string")
		assert.Contains(t, strVal.Str, "BPF_")
	})

	t.Run("Parse prctl option", func(t *testing.T) {
		t.Parallel()

		// PR_SET_NAME = 15
		data := []*pb.EventValue{
			{
				Name:  "option",
				Value: &pb.EventValue_Int32{Int32: 15},
			},
		}

		err := ParseDataFields(data, int(Prctl))
		require.NoError(t, err)

		optionField := GetFieldValue(data, "option")
		require.NotNil(t, optionField)

		// Should be converted to string
		strVal, ok := optionField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "option should be converted to string")
		assert.Contains(t, strVal.Str, "PR_")
	})

	t.Run("Parse access mode", func(t *testing.T) {
		t.Parallel()

		// R_OK | W_OK = 0x4 | 0x2 = 0x6
		data := []*pb.EventValue{
			{
				Name:  "mode",
				Value: &pb.EventValue_Int32{Int32: 0x6},
			},
		}

		err := ParseDataFields(data, int(Access))
		require.NoError(t, err)

		modeField := GetFieldValue(data, "mode")
		require.NotNil(t, modeField)

		// Should be converted to string
		strVal, ok := modeField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "mode should be converted to string")
		assert.Contains(t, strVal.Str, "_OK")
	})

	t.Run("Parse BPF prog type", func(t *testing.T) {
		t.Parallel()

		// BPF_PROG_TYPE_KPROBE = 6
		data := []*pb.EventValue{
			{
				Name:  "prog_type",
				Value: &pb.EventValue_Int32{Int32: 6},
			},
		}

		err := ParseDataFields(data, int(BpfAttach))
		require.NoError(t, err)

		progTypeField := GetFieldValue(data, "prog_type")
		require.NotNil(t, progTypeField)

		// Should be converted to string
		strVal, ok := progTypeField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "prog_type should be converted to string")
		assert.Contains(t, strVal.Str, "BPF_PROG_TYPE_")
	})

	t.Run("Parse BPF helpers", func(t *testing.T) {
		t.Parallel()

		// Set bit 1 (helper 1) and bit 10 (helper 10)
		helpersArray := []uint64{(1 << 1) | (1 << 10)}
		data := []*pb.EventValue{
			{
				Name:  "prog_helpers",
				Value: &pb.EventValue_UInt64Array{UInt64Array: &pb.UInt64Array{Value: helpersArray}},
			},
		}

		err := ParseDataFields(data, int(BpfAttach))
		require.NoError(t, err)

		helpersField := GetFieldValue(data, "prog_helpers")
		require.NotNil(t, helpersField)

		// Should be converted to string array
		strArrayVal, ok := helpersField.Value.(*pb.EventValue_StrArray)
		require.True(t, ok, "prog_helpers should be converted to string array")
		require.NotEmpty(t, strArrayVal.StrArray.Value)
		// Should have 2 helpers
		assert.Len(t, strArrayVal.StrArray.Value, 2)
	})

	t.Run("Parse BPF attach type", func(t *testing.T) {
		t.Parallel()

		// kprobe = 2
		data := []*pb.EventValue{
			{
				Name:  "attach_type",
				Value: &pb.EventValue_Int32{Int32: 2},
			},
		}

		err := ParseDataFields(data, int(BpfAttach))
		require.NoError(t, err)

		attachTypeField := GetFieldValue(data, "attach_type")
		require.NotNil(t, attachTypeField)

		// Should be converted to string
		strVal, ok := attachTypeField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "attach_type should be converted to string")
		assert.Equal(t, "kprobe", strVal.Str)
	})

	t.Run("Parse MemProtAlert", func(t *testing.T) {
		t.Parallel()

		data := []*pb.EventValue{
			{
				Name:  "alert",
				Value: &pb.EventValue_UInt32{UInt32: 1},
			},
			{
				Name:  "prot",
				Value: &pb.EventValue_Int32{Int32: 0x7}, // PROT_READ|PROT_WRITE|PROT_EXEC
			},
			{
				Name:  "prev_prot",
				Value: &pb.EventValue_Int32{Int32: 0x3}, // PROT_READ|PROT_WRITE
			},
		}

		err := ParseDataFields(data, int(MemProtAlert))
		require.NoError(t, err)

		alertField := GetFieldValue(data, "alert")
		require.NotNil(t, alertField)
		strVal, ok := alertField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "alert should be converted to string")
		assert.NotEmpty(t, strVal.Str)

		protField := GetFieldValue(data, "prot")
		require.NotNil(t, protField)
		strVal, ok = protField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "prot should be converted to string")
		assert.Contains(t, strVal.Str, "PROT_")

		prevProtField := GetFieldValue(data, "prev_prot")
		require.NotNil(t, prevProtField)
		strVal, ok = prevProtField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "prev_prot should be converted to string")
		assert.Contains(t, strVal.Str, "PROT_")
	})

	t.Run("No parsing for unrelated events", func(t *testing.T) {
		t.Parallel()

		// Event with an ID that doesn't need parsing
		data := []*pb.EventValue{
			{
				Name:  "some_arg",
				Value: &pb.EventValue_Int32{Int32: 42},
			},
		}

		err := ParseDataFields(data, int(SchedProcessFork))
		require.NoError(t, err)

		// Argument should remain unchanged
		someArgField := GetFieldValue(data, "some_arg")
		require.NotNil(t, someArgField)
		intVal, ok := someArgField.Value.(*pb.EventValue_Int32)
		require.True(t, ok, "some_arg should remain as int32")
		assert.Equal(t, int32(42), intVal.Int32)
	})

	t.Run("Missing argument doesn't cause error", func(t *testing.T) {
		t.Parallel()

		// Parsing SysEnter but syscall arg is missing
		data := []*pb.EventValue{
			{
				Name:  "other_arg",
				Value: &pb.EventValue_Int32{Int32: 42},
			},
		}

		err := ParseDataFields(data, int(SysEnter))
		require.NoError(t, err)
	})

	t.Run("Wrong type doesn't cause panic", func(t *testing.T) {
		t.Parallel()

		// syscall arg should be int32 but provided as string
		data := []*pb.EventValue{
			{
				Name:  "syscall",
				Value: &pb.EventValue_Str{Str: "not_a_number"},
			},
		}

		err := ParseDataFields(data, int(SysEnter))
		require.NoError(t, err)

		// Value should remain unchanged
		syscallField := GetFieldValue(data, "syscall")
		require.NotNil(t, syscallField)
		strVal, ok := syscallField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "syscall should remain as string")
		assert.Equal(t, "not_a_number", strVal.Str)
	})

	t.Run("Empty data slice", func(t *testing.T) {
		t.Parallel()

		data := []*pb.EventValue{}
		err := ParseDataFields(data, int(SysEnter))
		require.NoError(t, err)
	})

	t.Run("Nil values in data", func(t *testing.T) {
		t.Parallel()

		data := []*pb.EventValue{
			{
				Name:  "arg1",
				Value: nil,
			},
		}

		err := ParseDataFields(data, int(SysEnter))
		require.NoError(t, err)
	})

	t.Run("Pointer values formatted as hex", func(t *testing.T) {
		t.Parallel()

		data := []*pb.EventValue{
			{
				Name:  "ptr",
				Value: &pb.EventValue_Pointer{Pointer: 0x12345678abcd},
			},
			{
				Name:  "another_ptr",
				Value: &pb.EventValue_Pointer{Pointer: 0xdeadbeef},
			},
		}

		err := ParseDataFields(data, int(SchedProcessFork))
		require.NoError(t, err)

		// Verify pointers are converted to hex strings
		ptrField := GetFieldValue(data, "ptr")
		require.NotNil(t, ptrField)
		strVal, ok := ptrField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "pointer should be converted to string")
		assert.Equal(t, "0x12345678abcd", strVal.Str)

		anotherPtrField := GetFieldValue(data, "another_ptr")
		require.NotNil(t, anotherPtrField)
		strVal, ok = anotherPtrField.Value.(*pb.EventValue_Str)
		require.True(t, ok, "pointer should be converted to string")
		assert.Equal(t, "0xdeadbeef", strVal.Str)
	})
}

func TestParsePbDirfdAt(t *testing.T) {
	t.Parallel()

	t.Run("AT_FDCWD", func(t *testing.T) {
		dirfdVal := int32(-100) // AT_FDCWD
		field := &pb.EventValue{
			Name:  "dirfd",
			Value: &pb.EventValue_Int32{Int32: dirfdVal},
		}

		parseDirfdAt(field, uint64(dirfdVal))

		strVal, ok := field.Value.(*pb.EventValue_Str)
		require.True(t, ok, "dirfd should be converted to string")
		assert.Equal(t, "AT_FDCWD", strVal.Str)
	})

	t.Run("Regular fd", func(t *testing.T) {
		field := &pb.EventValue{
			Name:  "dirfd",
			Value: &pb.EventValue_Int32{Int32: 3},
		}

		parseDirfdAt(field, uint64(3))

		// Should remain unchanged (not AT_FDCWD)
		intVal, ok := field.Value.(*pb.EventValue_Int32)
		require.True(t, ok, "dirfd should remain as int32")
		assert.Equal(t, int32(3), intVal.Int32)
	})
}

// Additional tests can be added for other helper functions as needed
