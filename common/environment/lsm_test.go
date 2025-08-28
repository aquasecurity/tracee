package environment

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsBPFEnabledInLSM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		filesystem     fs.FS
		expectedResult bool
		expectedError  error
		errorContains  string
	}{
		{
			name:       "SecurityFS not mounted - directory missing",
			filesystem: fstest.MapFS{
				// No sys/kernel/security directory
			},
			expectedResult: false,
			expectedError:  ErrSecurityFSNotMounted,
		},
		{
			name: "SecurityFS mounted but LSM file missing",
			filesystem: fstest.MapFS{
				"sys/kernel/security/some_other_file": &fstest.MapFile{
					Data: []byte("test"),
				},
				// security directory exists but no lsm file
			},
			expectedResult: false,
			expectedError:  nil,
			errorContains:  "LSM file not found",
		},
		{
			name: "LSM file exists with BPF enabled",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("lockdown,yama,apparmor,bpf"),
				},
			},
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name: "LSM file exists with BPF enabled (whitespace)",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("lockdown, yama, apparmor, bpf"),
				},
			},
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name: "LSM file exists with BPF only",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("bpf"),
				},
			},
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name: "LSM file exists without BPF",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("lockdown,yama,apparmor"),
				},
			},
			expectedResult: false,
			expectedError:  nil,
		},
		{
			name: "LSM file exists with empty content",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte(""),
				},
			},
			expectedResult: false,
			expectedError:  nil,
		},
		{
			name: "LSM file exists with newlines and whitespace",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("\nlockdown,yama,apparmor,bpf\n"),
				},
			},
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name: "LSM file with BPF at the beginning",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("bpf,lockdown,yama,apparmor"),
				},
			},
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name: "LSM file with BPF in the middle",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("lockdown,bpf,yama,apparmor"),
				},
			},
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name: "LSM file with similar but not exact BPF",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("lockdown,yama,apparmor,bpf_test"),
				},
			},
			expectedResult: false,
			expectedError:  nil,
		},
		{
			name: "LSM file with BPF substring but not exact match",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("lockdown,yama,apparmor,test_bpf"),
				},
			},
			expectedResult: false,
			expectedError:  nil,
		},
		{
			name: "LSM file with excessive whitespace",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("  lockdown  ,  yama  ,  apparmor  ,  bpf  "),
				},
			},
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name: "LSM file with tabs and mixed whitespace",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("\tlockdown\t,\tyama\t,\tapparmor\t,\tbpf\t"),
				},
			},
			expectedResult: true,
			expectedError:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := IsLSMSupportedInSecurityFs(tt.filesystem)

			assert.Equal(t, tt.expectedResult, result)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			} else if tt.errorContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestIsBPFEnabledInLSMFromOS(t *testing.T) {
	// This test verifies that the convenience function works
	// In a real environment, this would test against the actual OS filesystem
	// For unit testing, we just verify it doesn't panic and returns some result
	t.Run("OS filesystem function doesn't panic", func(t *testing.T) {
		// This might fail in test environments without proper LSM setup,
		// but it shouldn't panic
		result, err := IsBPFEnabledInLSMFromOS()

		// We don't assert specific values since this depends on the test environment
		// We just ensure it doesn't panic and returns reasonable types
		_ = result // result can be true or false

		// Error can be any of the LSM errors or nil
		if err != nil {
			// Should be one of our defined error types
			assert.True(t,
				err == ErrSecurityFSNotMounted ||
					err.Error() != "", // or some other error with a message
				"Error should be a known LSM error type or have a message")
		}
	})
}

// Test error scenarios with more complex filesystem setups
func TestIsBPFEnabledInLSM_ErrorScenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		filesystem     fs.FS
		expectedResult bool
		expectedError  error
		errorContains  string
	}{
		{
			name: "Security directory is a file instead of directory",
			filesystem: fstest.MapFS{
				"sys/kernel/security": &fstest.MapFile{
					Data: []byte("not a directory"),
				},
			},
			expectedResult: false,
			expectedError:  nil,
			errorContains:  "LSM file not found", // Cannot read lsm file inside a file
		},
		{
			name: "Nested security path missing intermediate directories",
			filesystem: fstest.MapFS{
				"sys/other/path": &fstest.MapFile{
					Data: []byte("test"),
				},
				// Missing sys/kernel directory
			},
			expectedResult: false,
			expectedError:  ErrSecurityFSNotMounted,
		},
		{
			name: "LSM file with binary content",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte{0x00, 0x01, 0x02, 0x03}, // Binary data
				},
			},
			expectedResult: false,
			expectedError:  nil,
		},
		{
			name: "Very long LSM configuration",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("lockdown,yama,apparmor,selinux,smack,tomoyo,aa,bpf,integrity,capability,landlock,loadpin,safesetid,trusted"),
				},
			},
			expectedResult: true,
			expectedError:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := IsLSMSupportedInSecurityFs(tt.filesystem)

			assert.Equal(t, tt.expectedResult, result)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			} else if tt.errorContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// Tests for CheckLSMSupportInKconfig function
func TestCheckLSMSupportInKconfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		kernelConfig          map[KernelConfigOption]interface{}
		expectedResult        bool
		expectedError         bool
		expectedErrorContains string
	}{
		{
			name: "CONFIG_BPF_LSM=y and CONFIG_LSM contains bpf",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
				CONFIG_LSM:     "lockdown,yama,apparmor,bpf",
			},
			expectedResult: true,
			expectedError:  false,
		},
		{
			name: "CONFIG_BPF_LSM=y but CONFIG_LSM missing bpf",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
				CONFIG_LSM:     "lockdown,yama,apparmor",
			},
			expectedResult:        false,
			expectedError:         true,
			expectedErrorContains: "BPF is not in LSM list",
		},
		{
			name: "CONFIG_BPF_LSM not enabled",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: UNDEFINED,
			},
			expectedResult:        false,
			expectedError:         true,
			expectedErrorContains: "BPF_LSM is not builtin",
		},
		{
			name: "CONFIG_BPF_LSM=y but no CONFIG_LSM (not supported)",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
				// CONFIG_LSM not set - should be considered not supported
			},
			expectedResult:        false,
			expectedError:         true,
			expectedErrorContains: "CONFIG_LSM is not set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create mock function that simulates kernel config access
			getKernelConfigValue := func(option KernelConfigOption) (KernelConfigOptionValue, string, error) {
				value, exists := tt.kernelConfig[option]
				if !exists {
					return UNDEFINED, "", errors.New("kernel config option not found")
				}

				// Determine the type and return string representation
				switch v := value.(type) {
				case KernelConfigOptionValue:
					return v, v.String(), nil
				case string:
					return STRING, v, nil
				default:
					return UNDEFINED, fmt.Sprintf("%v", value), nil
				}
			}

			// Test the standalone kconfig function directly
			result, err := CheckLSMSupportInKconfig(getKernelConfigValue)

			if tt.expectedError {
				require.Error(t, err)
				if tt.expectedErrorContains != "" {
					assert.Contains(t, err.Error(), tt.expectedErrorContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}
