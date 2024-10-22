package proc

import (
	"testing"
	"unsafe"

	"github.com/google/go-cmp/cmp"
)

const (
	// ensure that the test will fail if the ProcStat struct size changes
	maxProcStatLength = 8
)

func TestProcStatSize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
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

	for _, tc := range testCases {
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

func TestProcStatParsing(t *testing.T) {
	t.Parallel()

	filePath, err := createMockStatFile()
	if err != nil {
		t.Fatalf("Failed to create mock stat file: %v", err)
	}

	testCases := []struct {
		name     string
		expected ProcStat
	}{
		{
			name: "Correct parsing of mock stat file",
			expected: ProcStat{
				startTime: 46236871,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := newProcStat(filePath)
			if err != nil {
				t.Fatalf("Error parsing the proc stat: %v", err)
			}

			if !cmp.Equal(*result, tc.expected, cmp.AllowUnexported(ProcStat{})) {
				t.Errorf("Expected: %+v, but got: %+v", tc.expected, result)
			}
		})
	}
}
