package environment

import (
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsLSMSupportedInSecurityFs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		filesystem     fs.FS
		expectedResult bool
		expectedError  error
		errorContains  string
	}{
		{
			name: "LSM file exists with BPF enabled",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("lockdown,yama,apparmor,bpf"),
				},
			},
			expectedResult: true,
		},
		{
			name: "LSM file exists with BPF only",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("bpf"),
				},
			},
			expectedResult: true,
		},
		{
			name: "LSM file exists without BPF",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("lockdown,yama,apparmor"),
				},
			},
			expectedResult: false,
		},
		{
			name: "LSM file exists with empty content",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte(""),
				},
			},
			expectedResult: false,
		},
		{
			name: "LSM file with similar but not exact BPF",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("lockdown,yama,apparmor,bpf_test"),
				},
			},
			expectedResult: false,
		},
		{
			name: "LSM file with whitespace and formatting",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("  lockdown  ,  yama  ,  apparmor  ,  bpf  "),
				},
			},
			expectedResult: true,
		},
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
		},
		{
			name: "Security directory is a file instead of directory",
			filesystem: fstest.MapFS{
				"sys/kernel/security": &fstest.MapFile{
					Data: []byte("not a directory"),
				},
			},
			expectedResult: false,
			errorContains:  "security directory sys/kernel/security is not a directory",
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

func TestCheckLSMSupport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		filesystem            fs.FS
		kernelConfig          map[KernelConfigOption]interface{}
		expectedResult        bool
		expectedErrorContains string
	}{
		{
			name: "SecurityFS shows BPF is supported",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("lockdown,yama,apparmor,bpf"),
				},
			},
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
			},
			expectedResult: true,
		},
		{
			name: "SecurityFS shows BPF is not supported",
			filesystem: fstest.MapFS{
				"sys/kernel/security/lsm": &fstest.MapFile{
					Data: []byte("lockdown,yama,apparmor"),
				},
			},
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
			},
			expectedResult: false,
		},
		{
			name: "LSM file not found - should return false without error",
			filesystem: fstest.MapFS{
				"sys/kernel/security/some_other_file": &fstest.MapFile{
					Data: []byte("test"),
				},
			},
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
			},
			expectedResult: false,
		},
		{
			name: "SecurityFS not mounted - fallback to kernel config with BPF enabled",
			filesystem: fstest.MapFS{
				// No sys/kernel/security directory
				"proc/cmdline": &fstest.MapFile{
					Data: []byte("root=/dev/sda1 lsm=lockdown,bpf"),
				},
			},
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
				CONFIG_LSM:     "lockdown,yama,apparmor,bpf",
			},
			expectedResult: true,
		},
		{
			name: "SecurityFS access error - fallback to kernel config",
			filesystem: fstest.MapFS{
				"sys/kernel/security": &fstest.MapFile{
					Data: []byte("not a directory"),
				},
				"proc/cmdline": &fstest.MapFile{
					Data: []byte("root=/dev/sda1 lsm=lockdown,bpf"),
				},
			},
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
				CONFIG_LSM:     "lockdown,yama,apparmor,bpf",
			},
			expectedResult: true,
		},
		{
			name: "CONFIG_BPF_LSM=y and CONFIG_LSM contains bpf",
			filesystem: fstest.MapFS{
				// No securityfs - will fallback to kernel config
				"proc/cmdline": &fstest.MapFile{
					Data: []byte("root=/dev/sda1"),
				},
			},
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
				CONFIG_LSM:     "lockdown,yama,apparmor,bpf",
			},
			expectedResult: true,
		},
		{
			name: "CONFIG_BPF_LSM=y but CONFIG_LSM missing bpf",
			filesystem: fstest.MapFS{
				// No securityfs - will fallback to kernel config
				"proc/cmdline": &fstest.MapFile{
					Data: []byte("root=/dev/sda1"),
				},
			},
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
				CONFIG_LSM:     "lockdown,yama,apparmor",
			},
			expectedResult: false,
		},
		{
			name: "CONFIG_BPF_LSM not enabled",
			filesystem: fstest.MapFS{
				"proc/cmdline": &fstest.MapFile{
					Data: []byte("root=/dev/sda1"),
				},
			},
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: UNDEFINED,
			},
			expectedResult:        false,
			expectedErrorContains: "BPF_LSM is not builtin",
		},
		{
			name: "CONFIG_BPF_LSM=y but no CONFIG_LSM (depends on boot params)",
			filesystem: fstest.MapFS{
				// No securityfs - will fallback to kernel config
				"proc/cmdline": &fstest.MapFile{
					Data: []byte("root=/dev/sda1"),
				},
			},
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
				// CONFIG_LSM not set - should fallback to boot params check
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create mock function that simulates kernel config access
			getKernelConfigValue := func(option KernelConfigOption) (KernelConfigOptionValue, string, error) {
				value, exists := tt.kernelConfig[option]
				if !exists {
					return UNDEFINED, "", nil
				}

				switch v := value.(type) {
				case KernelConfigOptionValue:
					return v, v.String(), nil
				case string:
					return STRING, v, nil
				default:
					return UNDEFINED, "", fmt.Errorf("unknown type: %T", v)
				}
			}

			result, err := CheckLSMSupport(tt.filesystem, getKernelConfigValue)

			assert.Equal(t, tt.expectedResult, result)

			if tt.expectedErrorContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// Tests for CheckBPFLSMInKernelConfig function
func TestCheckBPFLSMInKernelConfig(t *testing.T) {
	tests := []struct {
		name           string
		kernelConfig   map[KernelConfigOption]interface{}
		expectedResult bool
		expectedError  bool
		errorContains  string
	}{
		{
			name: "CONFIG_BPF_LSM=y (builtin)",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
			},
			expectedResult: true,
			expectedError:  false,
		},
		{
			name: "CONFIG_BPF_LSM=m (module - not supported)",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: MODULE,
			},
			expectedResult: false,
			expectedError:  true,
			errorContains:  "BPF_LSM is not builtin",
		},
		{
			name:         "CONFIG_BPF_LSM not set",
			kernelConfig: map[KernelConfigOption]interface{}{
				// CONFIG_BPF_LSM not set
			},
			expectedResult: false,
			expectedError:  true,
			errorContains:  "BPF_LSM is not builtin",
		},
		{
			name: "CONFIG_BPF_LSM=n (disabled)",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: UNDEFINED,
			},
			expectedResult: false,
			expectedError:  true,
			errorContains:  "BPF_LSM is not builtin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getKernelConfigValue := func(option KernelConfigOption) (KernelConfigOptionValue, string, error) {
				value, exists := tt.kernelConfig[option]
				if !exists {
					return UNDEFINED, "", nil
				}

				switch v := value.(type) {
				case KernelConfigOptionValue:
					return v, v.String(), nil
				default:
					return UNDEFINED, "", fmt.Errorf("unknown type: %T", v)
				}
			}

			result, err := CheckBPFLSMInKernelConfig(getKernelConfigValue)

			assert.Equal(t, tt.expectedResult, result)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// Tests for CheckBPFInKernelConfigLSM function
func TestCheckBPFInKernelConfigLSM(t *testing.T) {
	tests := []struct {
		name           string
		kernelConfig   map[KernelConfigOption]interface{}
		expectedResult bool
		expectedError  bool
		errorContains  string
	}{
		{
			name: "CONFIG_LSM contains bpf",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_LSM: "lockdown,yama,apparmor,bpf",
			},
			expectedResult: true,
			expectedError:  false,
		},
		{
			name: "CONFIG_LSM does not contain bpf",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_LSM: "lockdown,yama,apparmor",
			},
			expectedResult: false,
			expectedError:  false,
		},
		{
			name:         "CONFIG_LSM not set",
			kernelConfig: map[KernelConfigOption]interface{}{
				// CONFIG_LSM not set
			},
			expectedResult: false,
			expectedError:  false,
		},
		{
			name: "CONFIG_LSM is UNDEFINED",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_LSM: UNDEFINED,
			},
			expectedResult: false,
			expectedError:  false,
		},
		{
			name: "CONFIG_LSM contains only bpf",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_LSM: "bpf",
			},
			expectedResult: true,
			expectedError:  false,
		},
		{
			name: "CONFIG_LSM with spaces and exact substring match",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_LSM: "lockdown, bpf ,yama,bpf_lsm",
			},
			expectedResult: true,
			expectedError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getKernelConfigValue := func(option KernelConfigOption) (KernelConfigOptionValue, string, error) {
				value, exists := tt.kernelConfig[option]
				if !exists {
					return UNDEFINED, "", nil
				}

				switch v := value.(type) {
				case KernelConfigOptionValue:
					return v, v.String(), nil
				case string:
					return STRING, v, nil
				default:
					return UNDEFINED, "", fmt.Errorf("unknown type: %T", v)
				}
			}

			result, err := CheckBPFInKernelConfigLSM(getKernelConfigValue)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

// Tests for CheckBPFInBootParams function
func TestCheckBPFInBootParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		bootCmdline        string
		filesystem         fs.FS // For error cases with custom filesystem
		expectedBPFEnabled bool
		expectedParamFound bool
		expectedError      bool
		errorContains      string
	}{
		{
			name:               "No LSM parameter - should fallback to defaults",
			bootCmdline:        "root=/dev/sda1 quiet splash",
			expectedBPFEnabled: false,
			expectedParamFound: false,
			expectedError:      false,
		},
		{
			name:               "Empty LSM parameter - explicitly disabled",
			bootCmdline:        "root=/dev/sda1 lsm= quiet",
			expectedBPFEnabled: false,
			expectedParamFound: true,
			expectedError:      false,
		},
		{
			name:               "LSM parameter with BPF - explicitly enabled",
			bootCmdline:        "root=/dev/sda1 lsm=lockdown,bpf,yama quiet",
			expectedBPFEnabled: true,
			expectedParamFound: true,
			expectedError:      false,
		},
		{
			name:               "LSM parameter without BPF - explicitly disabled",
			bootCmdline:        "root=/dev/sda1 lsm=lockdown,yama,apparmor quiet",
			expectedBPFEnabled: false,
			expectedParamFound: true,
			expectedError:      false,
		},
		{
			name:               "LSM parameter with only BPF",
			bootCmdline:        "root=/dev/sda1 lsm=bpf quiet",
			expectedBPFEnabled: true,
			expectedParamFound: true,
			expectedError:      false,
		},
		{
			name:               "LSM parameter with BPF at beginning",
			bootCmdline:        "root=/dev/sda1 lsm=bpf,lockdown,yama quiet",
			expectedBPFEnabled: true,
			expectedParamFound: true,
			expectedError:      false,
		},
		{
			name:               "LSM parameter with similar but not exact BPF",
			bootCmdline:        "root=/dev/sda1 lsm=lockdown,bpf_test,yama quiet",
			expectedBPFEnabled: false,
			expectedParamFound: true,
			expectedError:      false,
		},
		{
			name:               "LSM parameter with BPF in middle",
			bootCmdline:        "root=/dev/sda1 lsm=lockdown,bpf,yama quiet",
			expectedBPFEnabled: true,
			expectedParamFound: true,
			expectedError:      false,
		},

		{
			name:               "Empty cmdline",
			bootCmdline:        "",
			expectedBPFEnabled: false,
			expectedParamFound: false,
			expectedError:      false,
		},
		{
			name:       "Missing proc/cmdline",
			filesystem: fstest.MapFS{
				// No proc/cmdline file
			},
			expectedBPFEnabled: false,
			expectedParamFound: false,
			expectedError:      true,
			errorContains:      "proc filesystem not available",
		},
		{
			name: "Proc directory missing",
			filesystem: fstest.MapFS{
				"other/file": &fstest.MapFile{
					Data: []byte("test"),
				},
			},
			expectedBPFEnabled: false,
			expectedParamFound: false,
			expectedError:      true,
			errorContains:      "proc filesystem not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create filesystem - use custom filesystem if provided, otherwise create from bootCmdline
			var mockFS fs.FS
			if tt.filesystem != nil {
				mockFS = tt.filesystem
			} else if tt.bootCmdline == "" {
				// Empty cmdline case
				mockFS = fstest.MapFS{
					"proc/cmdline": &fstest.MapFile{
						Data: []byte(""),
					},
				}
			} else {
				mockFS = fstest.MapFS{
					"proc/cmdline": &fstest.MapFile{
						Data: []byte(tt.bootCmdline),
					},
				}
			}

			result, err := CheckBPFInBootParams(mockFS)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				// Check that error result is zero value
				assert.Equal(t, LSMBootResult{}, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedBPFEnabled, result.BPFEnabled, "BPFEnabled mismatch")
				assert.Equal(t, tt.expectedParamFound, result.ParameterFound, "ParameterFound mismatch")
			}
		})
	}
}

// Tests for CheckBPFLSMConfigSupport function
func TestCheckBPFLSMConfigSupport(t *testing.T) {
	tests := []struct {
		name           string
		kernelConfig   map[KernelConfigOption]interface{}
		bootCmdline    string
		expectedResult bool
		expectedError  bool
		description    string
	}{
		{
			name: "Boot params enable BPF when CONFIG_LSM not set",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
				// CONFIG_LSM not set
			},
			bootCmdline:    "root=/dev/sda1 lsm=lockdown,bpf quiet",
			expectedResult: true,
			expectedError:  false,
			description:    "CONFIG_BPF_LSM=y, no CONFIG_LSM, boot params enable BPF → should work",
		},
		{
			name: "Boot params override CONFIG_LSM",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
				CONFIG_LSM:     "lockdown,yama,apparmor", // No BPF in kernel config
			},
			bootCmdline:    "root=/dev/sda1 lsm=lockdown,bpf quiet",
			expectedResult: true,
			expectedError:  false,
			description:    "Boot params override kernel config that doesn't have BPF",
		},
		{
			name: "Boot params disable BPF even though CONFIG_LSM has it",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
				CONFIG_LSM:     "lockdown,yama,apparmor,bpf",
			},
			bootCmdline:    "root=/dev/sda1 lsm=lockdown,yama quiet",
			expectedResult: false,
			expectedError:  false,
			description:    "Boot params disable BPF even though CONFIG_LSM has it",
		},
		{
			name: "No boot params, fallback to CONFIG_LSM with BPF",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
				CONFIG_LSM:     "lockdown,yama,apparmor,bpf",
			},
			bootCmdline:    "root=/dev/sda1 quiet",
			expectedResult: true,
			expectedError:  false,
			description:    "No LSM boot params, fallback to CONFIG_LSM which has BPF",
		},
		{
			name: "No boot params, fallback to CONFIG_LSM without BPF",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: BUILTIN,
				CONFIG_LSM:     "lockdown,yama,apparmor",
			},
			bootCmdline:    "root=/dev/sda1 quiet",
			expectedResult: false,
			expectedError:  false,
			description:    "No LSM boot params, fallback to CONFIG_LSM which doesn't have BPF",
		},
		{
			name: "CONFIG_BPF_LSM not enabled",
			kernelConfig: map[KernelConfigOption]interface{}{
				CONFIG_BPF_LSM: UNDEFINED,
			},
			bootCmdline:    "root=/dev/sda1 lsm=lockdown,bpf quiet",
			expectedResult: false,
			expectedError:  true,
			description:    "BPF LSM not compiled into kernel, boot params can't enable it",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock filesystem with boot cmdline
			mockFS := fstest.MapFS{
				"proc/cmdline": &fstest.MapFile{
					Data: []byte(tt.bootCmdline),
				},
			}

			// Create mock kernel config function
			getKernelConfigValue := func(option KernelConfigOption) (KernelConfigOptionValue, string, error) {
				value, exists := tt.kernelConfig[option]
				if !exists {
					return UNDEFINED, "", nil
				}

				switch v := value.(type) {
				case KernelConfigOptionValue:
					return v, v.String(), nil
				case string:
					return STRING, v, nil
				default:
					return UNDEFINED, "", fmt.Errorf("unknown type: %T", v)
				}
			}

			// Test the complete integration
			result, err := CheckBPFLSMConfigSupport(getKernelConfigValue, mockFS)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error but got none. %s", tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v. %s", err, tt.description)
					return
				}

				if result != tt.expectedResult {
					t.Errorf("Expected result %v, got %v. %s", tt.expectedResult, result, tt.description)
				}
			}
		})
	}
}
