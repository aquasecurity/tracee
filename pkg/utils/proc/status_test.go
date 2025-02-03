package proc

import (
	"os"
	"testing"
	"unsafe"

	"github.com/google/go-cmp/cmp"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

const (
	// ensure that the test will fail if the ProcStatus struct size changes
	maxProcStatusNameLength = 64 // https://elixir.bootlin.com/linux/v6.11.4/source/fs/proc/array.c#L99
	maxProcStatusLength     = 104
)

// TestProcStatus_PrintSizes prints the sizes of the structs used in the ProcStatus type.
// Run it as DEBUG test to see the output.
func TestProcStatus_PrintSizes(t *testing.T) {
	procStatus := ProcStatus{}
	tests.PrintStructSizes(t, os.Stdout, procStatus)
}

func TestProcStatusSize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		input        ProcStatus
		expectedSize uintptr
	}{
		{
			name:         "Empty string",
			input:        ProcStatus{name: ""},
			expectedSize: 40, // 40 bytes struct = [24 bytes (6 * int32)] + [16 bytes (string = 8 bytes pointer + 8 bytes length)]
		},
		{
			name:         "String with 64 characters (max length)",
			input:        ProcStatus{name: string(make([]byte, maxProcStatusNameLength))},
			expectedSize: maxProcStatusLength, // 104 bytes struct = [24 bytes (6 * int32)] + [16 bytes (string = 8 bytes pointer + 8 bytes length)] + [64 bytes (string content)]
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualSize := unsafe.Sizeof(tc.input) + uintptr(len(tc.input.name))

			if actualSize != tc.expectedSize {
				t.Errorf("Test case '%s' failed. Expected size: %d, but got: %d", tc.name, tc.expectedSize, actualSize)
			} else {
				t.Logf("Test case '%s' passed. Size: %d bytes", tc.name, actualSize)
			}
		})
	}
}

var statusContent = `
Name:   Utility Process
Umask:  0022
State:  R (running)
Tgid:   216448
Ngid:   0
Pid:    216447
PPid:   3994523
TracerPid:      0
Uid:    1000    1000    1000    1000
Gid:    1000    1000    1000    1000
FDSize: 128
Groups: 3 90 98 108 955 959 986 991 998 1000 
NStgid: 216443
NSpid:  216445
NSpgid: 216444
NSsid:  3994523
Kthread:        0
VmPeak:    10392 kB
VmSize:    10356 kB
VmLck:         0 kB
VmPin:         0 kB
VmHWM:      6400 kB
VmRSS:      6400 kB
RssAnon:            1536 kB
RssFile:            4864 kB
RssShmem:              0 kB
VmData:     1384 kB
VmStk:       136 kB
VmExe:      2860 kB
VmLib:      2372 kB
VmPTE:        64 kB
VmSwap:        0 kB
HugetlbPages:          0 kB
CoreDumping:    0
THP_enabled:    1
untag_mask:     0xffffffffffffffff
Threads:        1
SigQ:   0/253444
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000000000
SigIgn: 0000000000001000
SigCgt: 0000000000000440
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
NoNewPrivs:     0
Seccomp:        0
Seccomp_filters:        0
Speculation_Store_Bypass:       thread vulnerable
SpeculationIndirectBranch:      conditional enabled
Cpus_allowed:   ffffffff
Cpus_allowed_list:      0-31
Mems_allowed:   00000001
Mems_allowed_list:      0
voluntary_ctxt_switches:        1
nonvoluntary_ctxt_switches:     0
x86_Thread_features:
x86_Thread_features_locked:
`

func Test_newProcStatus(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		expected ProcStatus
	}{
		{
			name: "Correct parsing of mock status file",
			expected: ProcStatus{
				name:   "Utility Process",
				tgid:   216448,
				pid:    216447,
				pPid:   3994523,
				nstgid: 216443,
				nspid:  216445,
				nspgid: 216444,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			file := tests.CreateTempFile(t, statusContent)
			defer os.Remove(file.Name())

			result, err := newProcStatus(file.Name(), statusDefaultFields)
			if err != nil {
				t.Fatalf("Error parsing the proc status: %v", err)
			}

			if !cmp.Equal(*result, tc.expected, cmp.AllowUnexported(ProcStatus{})) {
				t.Errorf("Expected: %+v, but got: %+v", tc.expected, result)
			}
		})
	}
}
