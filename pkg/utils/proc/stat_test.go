package proc

import (
	"os"
	"testing"
	"unsafe"

	"github.com/google/go-cmp/cmp"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

const (
	// ensure that the test will fail if the ProcStat struct size changes
	maxProcStatLength = 8
)

// TestProcStat_PrintSizes prints the sizes of the structs used in the ProcStat type.
// Run it as DEBUG test to see the output.
func TestProcStat_PrintSizes(t *testing.T) {
	procStat := ProcStat{}
	tests.PrintStructSizes(t, os.Stdout, procStat)
}

func TestProcStatSize(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name         string
		input        ProcStat
		expectedSize uintptr
	}{
		{
			name: "Single field",
			input: ProcStat{
				startTime: 123456,
			},
			expectedSize: maxProcStatLength,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			actualSize := unsafe.Sizeof(tc.input)

			if actualSize != tc.expectedSize {
				t.Errorf("Test case '%s' failed. Expected size: %d, but got: %d", tc.name, tc.expectedSize, actualSize)
			} else {
				t.Logf("Test case '%s' passed. Size: %d bytes", tc.name, actualSize)
			}
		})
	}
}

var statContent = "3529367 (Isolated (((Web))) Co) S 3437358 3433422 3433422 0 -1 4194560 " +
	"50679 0 0 0 566 643 0 0 20 0 29 0 46236871 2609160192 33222 " +
	"18446744073709551615 94165013317536 94165014109840 140730010890672 " +
	"0 0 0 0 16846850 1082134264 0 0 0 17 29 0 0 0 0 0 94165014122560 " +
	"94165014122664 94165887094784 140730010895394 140730010895699 " +
	"140730010895699 140730010898399 -1\n"

func Test_newProcStat(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name     string
		expected ProcStat
	}{
		{
			name: "Correct parsing of startTime",
			expected: ProcStat{
				startTime: 46236871,
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			file := tests.CreateTempFile(t, statContent)
			defer os.Remove(file.Name())

			result, err := newProcStat(file.Name(), statDefaultFields)
			if err != nil {
				t.Fatalf("Error creating new ProcStat: %v", err)
			}

			if !cmp.Equal(*result, tc.expected, cmp.AllowUnexported(ProcStat{})) {
				t.Errorf("Expected: %+v, but got: %+v", tc.expected, result)
			}
		})
	}
}
