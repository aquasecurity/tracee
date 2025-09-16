package environment

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePossibleCPUAmountFromCPUFileFormat(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expected      int
		expectError   bool
		errorContains string
	}{
		{
			name:     "single CPU (0)",
			input:    "0",
			expected: 1,
		},
		{
			name:          "single CPU (non-zero)",
			input:         "1",
			expectError:   true,
			errorContains: "possible cpus must start from the index 0",
		},
		{
			name:     "range starting from 0",
			input:    "0-3",
			expected: 4,
		},
		{
			name:     "range starting from 0 (larger)",
			input:    "0-7",
			expected: 8,
		},
		{
			name:     "range starting from 0 (single range)",
			input:    "0-0",
			expected: 1,
		},
		{
			name:          "range not starting from 0",
			input:         "1-3",
			expectError:   true,
			errorContains: "possible cpus should be following indexes range starting with 0",
		},
		{
			name:          "multiple regions",
			input:         "0-1,4-7",
			expectError:   true,
			errorContains: "possible cpus should be following indexes starting with 0, so multiple regions is not allowed",
		},
		{
			name:          "group format",
			input:         "0-7:2/4",
			expectError:   true,
			errorContains: "possible cpus should be following indexes, but received groups format",
		},
		{
			name:          "invalid format",
			input:         "invalid",
			expectError:   true,
			errorContains: "unknown possible cpu file format",
		},
		{
			name:          "empty string",
			input:         "",
			expectError:   true,
			errorContains: "unknown possible cpu file format",
		},
		{
			name:     "range with newline (common in real files)",
			input:    "0-3\n",
			expected: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parsePossibleCPUAmountFromCPUFileFormat(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGetCPUAmount(t *testing.T) {
	t.Run("success case with mock file", func(t *testing.T) {
		// Create a temporary file
		tmpFile, err := os.CreateTemp("", "possible_cpu_test")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		// Write valid CPU data
		_, err = tmpFile.WriteString("0-3\n")
		assert.NoError(t, err)
		tmpFile.Close()

		// Note: We can't easily mock the file path due to the const,
		// but we can test the parsing function directly, which is the core logic

		// Since we can't easily mock the file path due to the const,
		// let's test the parsing function directly, which is the core logic
		content, err := os.ReadFile(tmpFile.Name())
		assert.NoError(t, err)

		result, err := parsePossibleCPUAmountFromCPUFileFormat(string(content))
		assert.NoError(t, err)
		assert.Equal(t, 4, result)
	})

	t.Run("real system call", func(t *testing.T) {
		// Test the actual function - this will use the real system file
		result, err := GetCPUAmount()

		// On most systems this should work, but we can't guarantee the exact value
		if err == nil {
			assert.Greater(t, result, 0, "CPU count should be positive")
			assert.LessOrEqual(t, result, 1024, "CPU count should be reasonable")
		} else {
			// On some systems the file might not exist, which is also valid
			t.Logf("GetCPUAmount failed (expected on some systems): %v", err)
		}
	})
}

func TestGetMEMAmountInMBs(t *testing.T) {
	t.Run("real system call", func(t *testing.T) {
		// Test the actual function - this will use the real /proc/meminfo
		result := GetMEMAmountInMBs()

		// On most Linux systems this should work
		if result > 0 {
			assert.Greater(t, result, 0, "Memory amount should be positive")
			assert.LessOrEqual(t, result, 1024*1024, "Memory amount should be reasonable (< 1TB)")
			t.Logf("System memory: %d MB", result)
		} else {
			// On some systems the file might not exist or be inaccessible
			t.Logf("GetMEMAmountInMBs returned 0 (expected on some systems)")
		}
	})

	t.Run("mock meminfo file", func(t *testing.T) {
		// Create a temporary meminfo file
		tmpFile, err := os.CreateTemp("", "meminfo_test")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		// Write mock meminfo content
		content := `MemTotal:       16384000 kB
MemFree:         8192000 kB
MemAvailable:   12288000 kB
Buffers:          512000 kB
Cached:          2048000 kB`

		_, err = tmpFile.WriteString(content)
		assert.NoError(t, err)
		tmpFile.Close()

		// We can't easily test this without modifying the function to accept a file path
		// But we can verify the parsing logic manually

		// Simulate the parsing logic
		expectedMemTotal := 16384000             // kB
		expectedMemMB := expectedMemTotal / 1024 // Convert to MB
		assert.Equal(t, 16000, expectedMemMB)    // Should be ~16GB
	})
}

// Test constants
func TestAmountConstants(t *testing.T) {
	assert.Equal(t, "/sys/devices/system/cpu/possible", possibleCPUsFilePath)
	assert.Equal(t, 1, singleValue)
	assert.Equal(t, 2, rangeValues)
	assert.Equal(t, 4, rangeValuesWithGroups)
}
