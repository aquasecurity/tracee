package parsers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsContainedInArgument(t *testing.T) {
	attachTests := []struct {
		testName          string
		rawArgument       uint64
		options           []SystemFunctionArgument
		expectedContained bool
		expectedValue     uint64
		expectedString    string
	}{
		{
			testName:          "no options present",
			rawArgument:       0x0,
			options:           []SystemFunctionArgument{CLONE_CHILD_CLEARTID},
			expectedContained: false,
		},
		{
			testName:          "present in self",
			rawArgument:       PTRACE_TRACEME.Value(),
			options:           []SystemFunctionArgument{PTRACE_TRACEME},
			expectedContained: true,
		},
		{
			testName:          "present in self multiple",
			rawArgument:       PTRACE_TRACEME.Value(),
			options:           []SystemFunctionArgument{PTRACE_TRACEME, PTRACE_TRACEME},
			expectedContained: true,
		},
		{
			testName:          "just not present",
			rawArgument:       PTRACE_PEEKTEXT.Value(),
			options:           []SystemFunctionArgument{PTRACE_TRACEME},
			expectedContained: true,
		},
		{
			testName:          "present1",
			rawArgument:       PTRACE_TRACEME.Value() | PTRACE_GETSIGMASK.Value(),
			options:           []SystemFunctionArgument{PTRACE_TRACEME, PTRACE_GETSIGMASK},
			expectedContained: true,
		},
		{
			testName:          "present2",
			rawArgument:       BPF_MAP_CREATE.Value(),
			options:           []SystemFunctionArgument{BPF_MAP_CREATE},
			expectedContained: true,
		},
		{
			testName:          "present3",
			rawArgument:       CAP_CHOWN.Value(),
			options:           []SystemFunctionArgument{CAP_CHOWN},
			expectedContained: true,
		},
	}

	for _, ts := range attachTests {
		t.Run(ts.testName, func(test *testing.T) {
			isContained := OptionAreContainedInArgument(ts.rawArgument, ts.options...)
			assert.Equal(test, ts.expectedContained, isContained)
		})
	}
}

func TestParseSetSocketOption(t *testing.T) {
	testCases := []struct {
		name          string
		parseValue    uint64
		expectedSting string
		expectedError bool
	}{
		{
			name:          "Normal value",
			parseValue:    SO_DEBUG.Value(),
			expectedSting: "SO_DEBUG",
			expectedError: false,
		},
		{
			name:          "Get changed value",
			parseValue:    SO_ATTACH_FILTER.Value(),
			expectedSting: "SO_ATTACH_FILTER",
			expectedError: false,
		},
		{
			name:          "Non existing value",
			parseValue:    10000000,
			expectedSting: "",
			expectedError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			opt, err := ParseSetSocketOption(testCase.parseValue)
			if testCase.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.expectedSting, opt.String())
		})
	}
}

func TestParseGetSocketOption(t *testing.T) {
	testCases := []struct {
		name          string
		parseValue    uint64
		expectedSting string
		expectedError bool
	}{
		{
			name:          "Normal value",
			parseValue:    SO_DEBUG.Value(),
			expectedSting: "SO_DEBUG",
			expectedError: false,
		},
		{
			name:          "Get changed value",
			parseValue:    SO_GET_FILTER.Value(),
			expectedSting: "SO_GET_FILTER",
			expectedError: false,
		},
		{
			name:          "Non existing value",
			parseValue:    10000000,
			expectedSting: "",
			expectedError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			opt, err := ParseGetSocketOption(testCase.parseValue)
			if testCase.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.expectedSting, opt.String())
		})
	}
}

func TestParseBPFProgType(t *testing.T) {
	testCases := []struct {
		name          string
		parseValue    uint64
		expectedSting string
		expectedError bool
	}{
		{
			name:          "Type tracepoint",
			parseValue:    BPFProgTypeTracepoint.Value(),
			expectedSting: "BPF_PROG_TYPE_TRACEPOINT",
			expectedError: false,
		},
		{
			name:          "Non existing type",
			parseValue:    10000000,
			expectedSting: "BPF_PROG_TYPE_UNSPEC",
			expectedError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			opt, err := ParseBPFProgType(testCase.parseValue)
			if testCase.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.expectedSting, opt.String())
		})
	}
}

func TestParseMmapFlags(t *testing.T) {
	testCases := []struct {
		name          string
		parseValue    uint64
		expectedSting string
	}{
		{
			name:          "Single value",
			parseValue:    MapGrowsdown.Value(),
			expectedSting: "MAP_GROWSDOWN",
		},
		{
			name:          "Multiple values",
			parseValue:    MapGrowsdown.Value() | MapStack.Value() | MapExecutable.Value(),
			expectedSting: "MAP_GROWSDOWN|MAP_EXECUTABLE|MAP_STACK",
		},
		{
			name:          "Huge table size flag",
			parseValue:    MapHuge2MB.Value(),
			expectedSting: "MAP_HUGE_2MB",
		},
		{
			name:          "Huge table custom size flag",
			parseValue:    19 << HugetlbFlagEncodeShift,
			expectedSting: "MAP_HUGE_512KB",
		},
		{
			name:          "Huge table custom size flag with normal flags",
			parseValue:    (19 << HugetlbFlagEncodeShift) | MapHugetlb.Value() | MapExecutable.Value(),
			expectedSting: "MAP_EXECUTABLE|MAP_HUGETLB|MAP_HUGE_512KB",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			flags := ParseMmapFlags(testCase.parseValue)
			assert.Equal(t, testCase.expectedSting, flags.String())
		})
	}
}

func TestParseGupFlags(t *testing.T) {
	testCases := []struct {
		name          string
		parseValue    uint64
		expectedSting string
	}{
		{
			name:          "Single value",
			parseValue:    FOLL_PIN.Value(),
			expectedSting: "FOLL_PIN",
		},
		{
			name:          "Multiple values",
			parseValue:    FOLL_NOWAIT.Value() | FOLL_ANON.Value() | FOLL_PIN.Value(),
			expectedSting: "FOLL_NOWAIT|FOLL_ANON|FOLL_PIN",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			flags := ParseGUPFlags(testCase.parseValue)
			assert.Equal(t, testCase.expectedSting, flags.String())
		})
	}
}

func TestParseLegacyGupFlags(t *testing.T) {
	testCases := []struct {
		name          string
		parseValue    uint64
		expectedSting string
	}{
		{
			name:          "Single value",
			parseValue:    LEGACY_FOLL_PIN.Value(),
			expectedSting: "FOLL_PIN",
		},
		{
			name:          "Multiple values",
			parseValue:    LEGACY_FOLL_TOUCH.Value() | LEGACY_FOLL_MIGRATION.Value() | LEGACY_FOLL_PIN.Value(),
			expectedSting: "FOLL_TOUCH|FOLL_MIGRATION|FOLL_PIN",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			flags := ParseLegacyGUPFlags(testCase.parseValue)
			assert.Equal(t, testCase.expectedSting, flags.String())
		})
	}
}

func TestParseVmFlags(t *testing.T) {
	testCases := []struct {
		name          string
		parseValue    uint64
		expectedSting string
	}{
		{
			name:          "Single value",
			parseValue:    VM_IO.Value(),
			expectedSting: "VM_IO",
		},
		{
			name:          "Multiple values",
			parseValue:    VM_MAYSHARE.Value() | VM_SEQ_READ.Value() | VM_PAT.Value(),
			expectedSting: "VM_MAYSHARE|VM_SEQ_READ|VM_PAT",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			flags := ParseVmFlags(testCase.parseValue)
			assert.Equal(t, testCase.expectedSting, flags.String())
		})
	}
}

func TestParseFsNotifyMask(t *testing.T) {
	testCases := []struct {
		name          string
		parseValue    uint64
		expectedSting string
	}{
		{
			name:          "Single value",
			parseValue:    FS_CREATE.Value(),
			expectedSting: "FS_CREATE",
		},
		{
			name:          "Multiple values",
			parseValue:    FS_OPEN_PERM.Value() | FS_ACCESS_PERM.Value() | FS_OPEN_EXEC_PERM.Value(),
			expectedSting: "FS_OPEN_PERM|FS_ACCESS_PERM|FS_OPEN_EXEC_PERM",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			flags := ParseFsNotifyMask(testCase.parseValue)
			assert.Equal(t, testCase.expectedSting, flags.String())
		})
	}
}

func TestParseFsNotifyObjType(t *testing.T) {
	testCases := []struct {
		name          string
		parseValue    uint64
		expectedSting string
		expectedError bool
	}{
		{
			name:          "Type vfsmount",
			parseValue:    FSNOTIFY_OBJ_TYPE_VFSMOUNT.Value(),
			expectedSting: "FSNOTIFY_OBJ_TYPE_VFSMOUNT",
			expectedError: false,
		},
		{
			name:          "Non existing type",
			parseValue:    10000000,
			expectedSting: "",
			expectedError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			opt, err := ParseFsNotifyObjType(testCase.parseValue)
			if testCase.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.expectedSting, opt.String())
		})
	}
}
