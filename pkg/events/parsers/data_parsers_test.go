package parsers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_optionsAreContainedInArgument(t *testing.T) {
	attachTests := []struct {
		testName          string
		rawArgument       uint64
		options           []uint64
		expectedContained bool
		expectedValue     uint64
		expectedString    string
	}{
		{
			testName:          "no options present",
			rawArgument:       0x0,
			options:           []uint64{CLONE_CHILD_CLEARTID.Value()},
			expectedContained: false,
		},
		{
			testName:          "present in self",
			rawArgument:       PTRACE_TRACEME.Value(),
			options:           []uint64{PTRACE_TRACEME.Value()},
			expectedContained: true,
		},
		{
			testName:          "present in self multiple",
			rawArgument:       PTRACE_TRACEME.Value(),
			options:           []uint64{PTRACE_TRACEME.Value(), PTRACE_TRACEME.Value()},
			expectedContained: true,
		},
		{
			testName:          "just not present",
			rawArgument:       PTRACE_PEEKTEXT.Value(),
			options:           []uint64{PTRACE_TRACEME.Value()},
			expectedContained: true,
		},
		{
			testName:          "just not present",
			rawArgument:       PTRACE_TRACEME.Value(),
			options:           []uint64{PTRACE_TRACEME.Value()},
			expectedContained: true,
		},
		{
			testName:          "present1",
			rawArgument:       PTRACE_TRACEME.Value() | PTRACE_GETSIGMASK.Value(),
			options:           []uint64{PTRACE_TRACEME.Value(), PTRACE_GETSIGMASK.Value()},
			expectedContained: true,
		},
		{
			testName:          "present2",
			rawArgument:       BPF_MAP_CREATE.Value(),
			options:           []uint64{BPF_MAP_CREATE.Value()},
			expectedContained: true,
		},
		{
			testName:          "present3",
			rawArgument:       CAP_CHOWN.Value(),
			options:           []uint64{CAP_CHOWN.Value()},
			expectedContained: true,
		},
		{
			testName:          "not present1",
			rawArgument:       CAP_CHOWN.Value(),
			options:           []uint64{CAP_DAC_OVERRIDE.Value()},
			expectedContained: false,
		},
		{
			testName:          "not present2",
			rawArgument:       CAP_CHOWN.Value() | CAP_DAC_READ_SEARCH.Value(),
			options:           []uint64{CAP_DAC_OVERRIDE.Value(), CAP_DAC_READ_SEARCH.Value()},
			expectedContained: false,
		},
	}

	for _, ts := range attachTests {
		t.Run(ts.testName, func(test *testing.T) {
			isContained := optionsAreContainedInArgument(ts.rawArgument, ts.options...)
			assert.Equal(test, ts.expectedContained, isContained)
		})
	}
}

func Test_optionIsContainedInArgument(t *testing.T) {
	attachTests := []struct {
		testName          string
		rawArgument       uint64
		option            uint64
		expectedContained bool
	}{
		{
			testName:          "no options present",
			rawArgument:       0x0,
			option:            CLONE_CHILD_CLEARTID.Value(),
			expectedContained: false,
		},
		{
			testName:          "present in self",
			rawArgument:       PTRACE_TRACEME.Value(),
			option:            PTRACE_TRACEME.Value(),
			expectedContained: true,
		},
		{
			testName:          "just not present",
			rawArgument:       PTRACE_PEEKTEXT.Value(),
			option:            PTRACE_TRACEME.Value(),
			expectedContained: true,
		},
		{
			testName:          "present",
			rawArgument:       PTRACE_TRACEME.Value() | PTRACE_GETSIGMASK.Value(),
			option:            PTRACE_GETSIGMASK.Value(),
			expectedContained: true,
		},
		{
			testName:          "not present",
			rawArgument:       CAP_CHOWN.Value(),
			option:            CAP_DAC_OVERRIDE.Value(),
			expectedContained: false,
		},
	}

	for _, ts := range attachTests {
		t.Run(ts.testName, func(test *testing.T) {
			isContained := optionIsContainedInArgument(ts.rawArgument, ts.option)
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

func TestParseMmapProt(t *testing.T) {
	testCases := []struct {
		name          string
		parseValue    uint64
		expectedSting string
	}{
		{
			name:          "Single value",
			parseValue:    PROT_NONE.Value(),
			expectedSting: "PROT_NONE",
		},
		{
			name:          "Single value",
			parseValue:    PROT_READ.Value(),
			expectedSting: "PROT_READ",
		},
		{
			name:          "Multiple values",
			parseValue:    PROT_READ.Value() | PROT_WRITE.Value() | PROT_EXEC.Value(),
			expectedSting: "PROT_READ|PROT_WRITE|PROT_EXEC",
		},
		{
			name:          "Multiple values with unknown",
			parseValue:    PROT_READ.Value() | PROT_WRITE.Value() | PROT_EXEC.Value() | 10000000,
			expectedSting: "PROT_READ|PROT_WRITE|PROT_EXEC",
		},
		{
			name:          "Non existing value",
			parseValue:    10000000,
			expectedSting: "",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			flags := ParseMmapProt(testCase.parseValue)
			assert.Equal(t, testCase.expectedSting, flags.String())
		})
	}
}
