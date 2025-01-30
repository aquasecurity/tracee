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

// TestProcStatus_PrintSizes prints the sizes of the structs used in the ProcStatus type.
// Run it as DEBUG test to see the output.
func TestProcStatus_PrintSizes(t *testing.T) {
	procStatus := ProcStatus{}
	tests.PrintStructSizes(t, os.Stdout, procStatus)
}

func TestProcStatusParsing(t *testing.T) {
	t.Parallel()

	filePath, err := createMockStatusFile()
	if err != nil {
		t.Fatalf("Failed to create mock status file: %v", err)
	}

	testCases := []struct {
		name     string
		expected ProcStatus
	}{
		{
			name: "Correct parsing of mock status file",
			expected: ProcStatus{
				name:   "Utility Process",
				tgid:   216447,
				pid:    216447,
				pPid:   3994523,
				nstgid: 216447,
				nspid:  216447,
				nspgid: 216447,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := newProcStatus(filePath)
			if err != nil {
				t.Fatalf("Error parsing the proc status: %v", err)
			}

			if !cmp.Equal(*result, tc.expected, cmp.AllowUnexported(ProcStatus{})) {
				t.Errorf("Expected: %+v, but got: %+v", tc.expected, result)
			}
		})
	}
}
