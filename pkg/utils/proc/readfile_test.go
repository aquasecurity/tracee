package proc

import (
	"bytes"
	"os"
	"testing"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

func TestReadFile(t *testing.T) {
	tt := []struct {
		name           string
		content        string
		expectedOutput string
		expectedErr    error
	}{
		{
			name:           "Empty File",
			content:        "",
			expectedOutput: "",
			expectedErr:    nil,
		},
		{
			name:           "Small File",
			content:        "Hello, world!",
			expectedOutput: "Hello, world!",
			expectedErr:    nil,
		},
		{
			name:           "Exact Buffer Size",
			content:        string(bytes.Repeat([]byte("A"), 512)),
			expectedOutput: string(bytes.Repeat([]byte("A"), 512)),
			expectedErr:    nil,
		},
		{
			name:           "Larger Than Buffer Size",
			content:        string(bytes.Repeat([]byte("B"), 1024)),
			expectedOutput: string(bytes.Repeat([]byte("B"), 1024)),
			expectedErr:    nil,
		},
		{
			name:           "Multibyte Characters",
			content:        "こんにちは世界",
			expectedOutput: "こんにちは世界",
			expectedErr:    nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			tempFile := tests.CreateTempFile(t, tc.content)
			defer os.Remove(tempFile.Name())

			// test
			output, err := ReadFile(tempFile.Name(), 512)

			// verify
			if !bytes.Equal(output, []byte(tc.expectedOutput)) {
				t.Errorf("Expected output %q, got %q", tc.expectedOutput, string(output))
			}
			if err != tc.expectedErr {
				t.Errorf("Expected error %v, got %v", tc.expectedErr, err)
			}
		})
	}
}
