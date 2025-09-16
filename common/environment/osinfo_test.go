package environment

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetOSInfo(t *testing.T) {
	testCases := []struct {
		testName                  string
		osReleaseFilePath         string
		expectedOSReleaseFilePath string
		expectedOSReleaseID       OSReleaseID
		expectedError             error
	}{
		{
			testName:                  "env os-release filepath",
			osReleaseFilePath:         "testdata/os-release-debian",
			expectedOSReleaseFilePath: "testdata/os-release-debian",
			expectedOSReleaseID:       DEBIAN,
			expectedError:             nil,
		},
		{
			testName:                  "env os-release filepath",
			osReleaseFilePath:         "testdata/os-release-ubuntu",
			expectedOSReleaseFilePath: "testdata/os-release-ubuntu",
			expectedOSReleaseID:       UBUNTU,
			expectedError:             nil,
		},
		{
			testName:                  "env os-release filepath",
			osReleaseFilePath:         "testdata/os-release-centos",
			expectedOSReleaseFilePath: "testdata/os-release-centos",
			expectedOSReleaseID:       CENTOS,
			expectedError:             nil,
		},
		{
			testName:                  "env os-release filepath",
			osReleaseFilePath:         "testdata/os-release-rhel",
			expectedOSReleaseFilePath: "testdata/os-release-rhel",
			expectedOSReleaseID:       RHEL,
			expectedError:             nil,
		},
		{
			testName:                  "env os-release filepath",
			osReleaseFilePath:         "testdata/os-release-almalinux",
			expectedOSReleaseFilePath: "testdata/os-release-almalinux",
			expectedOSReleaseID:       ALMA,
			expectedError:             nil,
		},
		{
			testName:                  "default os-release filepath",
			osReleaseFilePath:         "",
			expectedOSReleaseFilePath: "/etc/os-release",
			expectedError:             nil,
		},
		{
			testName:                  "non-existent os-release filepath",
			osReleaseFilePath:         "testdata/release",
			expectedOSReleaseFilePath: "testdata/release",
			expectedError:             errors.New("could not open LIBBPFGO_OSRELEASE_FILE testdata/release"),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.testName, func(t *testing.T) {
			var err error
			err = os.Setenv("LIBBPFGO_OSRELEASE_FILE", tt.osReleaseFilePath)
			assert.NoError(t, err)

			osInfo, err := GetOSInfo()
			if tt.expectedError != nil {
				assert.Equal(t, tt.expectedError, err)
				return
			}
			// covering unexpected uname error
			if err != nil {
				assert.ErrorContains(t, err, "uname")
				return
			}
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedOSReleaseFilePath, osInfo.GetOSReleaseFilePath())
			if tt.expectedOSReleaseID > 0 {
				assert.Equal(t, tt.expectedOSReleaseID, osInfo.GetOSReleaseID())
			}
		})
	}
}

func TestOSInfo_CompareOSBaseKernelRelease(t *testing.T) {
	testCases := []struct {
		testName           string
		base               string
		given              string
		expectedComparison KernelVersionComparison
		expectedError      error
	}{
		{
			testName:           "older than",
			base:               "5.1.1",
			given:              "4.3.2",
			expectedComparison: KernelVersionOlder,
			expectedError:      nil,
		},
		{
			testName:           "equal",
			base:               "5.0",
			given:              "5.0",
			expectedComparison: KernelVersionEqual,
			expectedError:      nil,
		},
		{
			testName:           "newer than",
			base:               "3.1.1",
			given:              "4.3.2",
			expectedComparison: KernelVersionNewer,
			expectedError:      nil,
		},
		{
			testName:           "newer than (missing patch)",
			base:               "3.1",
			given:              "4.3.2",
			expectedComparison: KernelVersionNewer,
			expectedError:      nil,
		},
		{
			testName:           "newer than (missing minor and match)",
			base:               "3",
			given:              "4.3.2",
			expectedComparison: KernelVersionNewer,
			expectedError:      nil,
		},
		{
			testName:           "too many parts",
			base:               "3.0.0.0",
			given:              "4.3.2",
			expectedComparison: KernelVersionNewer,
			expectedError:      nil,
		},
		{
			testName:           "invalid, not a number",
			base:               "X.5.4",
			given:              "4.3.2",
			expectedComparison: KernelVersionInvalid,
			expectedError:      errors.New("invalid base kernel version value: X.5.4 issue with: X"),
		},
		{
			testName:           "real version - fedora",
			base:               "6.15.8-200.fc42.x86_64",
			given:              "4.3.2",
			expectedComparison: KernelVersionOlder,
			expectedError:      nil,
		},
		{
			testName:           "real version - wsl2",
			base:               "6.6.87.2-microsoft-standard-WSL2",
			given:              "4.3.2",
			expectedComparison: KernelVersionOlder,
			expectedError:      nil,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.testName, func(t *testing.T) {
			osInfo := &OSInfo{
				osReleaseFieldValues: map[OSReleaseField]string{
					OS_KERNEL_RELEASE: tt.base,
				},
			}
			comp, err := osInfo.CompareOSBaseKernelRelease(tt.given)
			assert.Equal(t, tt.expectedComparison, comp)
			assert.Equal(t, tt.expectedError, err)
		})
	}
}

// Test OSReleaseID String method
func TestOSReleaseID_String(t *testing.T) {
	tests := []struct {
		name     string
		id       OSReleaseID
		expected string
	}{
		{"Ubuntu", UBUNTU, "ubuntu"},
		{"Fedora", FEDORA, "fedora"},
		{"Arch", ARCH, "arch"},
		{"Debian", DEBIAN, "debian"},
		{"CentOS", CENTOS, "centos"},
		{"Stream", STREAM, "stream"},
		{"Alma", ALMA, "alma"},
		{"RHEL", RHEL, "rhel"},
		{"Unknown ID", OSReleaseID(999), ""}, // Unknown ID should return empty string
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.id.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test OSReleaseField String method
func TestOSReleaseField_String(t *testing.T) {
	tests := []struct {
		name     string
		field    OSReleaseField
		expected string
	}{
		{"OS Kernel Release", OS_KERNEL_RELEASE, "KERNEL_RELEASE"},
		{"OS ID", OS_ID, "ID"},
		{"OS Version ID", OS_VERSION_ID, "VERSION_ID"},
		{"OS Name", OS_NAME, "NAME"},
		{"Unknown field", OSReleaseField(999), ""}, // Unknown field should return empty string
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.field.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test OSBTFEnabled function
func TestOSBTFEnabled(t *testing.T) {
	t.Run("real system call", func(t *testing.T) {
		// Test the actual function - this will check the real system
		result := OSBTFEnabled()

		// We can't predict the result, but it should not panic
		// and should return a boolean
		assert.IsType(t, false, result)
		t.Logf("System BTF enabled: %v", result)
	})
}

// Test OSInfo methods with mock data
func TestOSInfo_GetOSReleaseFieldValue(t *testing.T) {
	osInfo := &OSInfo{
		osReleaseFieldValues: map[OSReleaseField]string{
			OS_ID:         `"ubuntu"`,
			OS_VERSION_ID: `"20.04"`,
			OS_NAME:       `"Ubuntu"`,
		},
	}

	tests := []struct {
		name     string
		field    OSReleaseField
		expected string
	}{
		{"get ID", OS_ID, "ubuntu"},                // Should trim quotes
		{"get VERSION_ID", OS_VERSION_ID, "20.04"}, // Should trim quotes
		{"get NAME", OS_NAME, "Ubuntu"},            // Should trim quotes
		{"get non-existent", OS_ARCH, ""},          // Should return empty for non-existent
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := osInfo.GetOSReleaseFieldValue(tt.field)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test OSInfo_GetOSReleaseAllFieldValues
func TestOSInfo_GetOSReleaseAllFieldValues(t *testing.T) {
	originalValues := map[OSReleaseField]string{
		OS_ID:         "ubuntu",
		OS_VERSION_ID: "20.04",
		OS_NAME:       "Ubuntu",
	}

	osInfo := &OSInfo{
		osReleaseFieldValues: originalValues,
	}

	result := osInfo.GetOSReleaseAllFieldValues()

	assert.NotNil(t, result)
	assert.Equal(t, originalValues[OS_ID], result[OS_ID])
	assert.Equal(t, originalValues[OS_VERSION_ID], result[OS_VERSION_ID])
	assert.Equal(t, originalValues[OS_NAME], result[OS_NAME])

	// Verify it's a copy (modifying result shouldn't affect original)
	result[OS_ID] = "modified"
	assert.Equal(t, "ubuntu", osInfo.osReleaseFieldValues[OS_ID])
}

// Test FtraceEnabled function
func TestFtraceEnabled(t *testing.T) {
	t.Run("real system call", func(t *testing.T) {
		// Test the actual function - this will check the real system
		result, err := FtraceEnabled()

		// We can't predict the result, but it should not panic
		if err == nil {
			assert.IsType(t, false, result)
			t.Logf("System ftrace enabled: %v", result)
		} else {
			// On some systems the ftrace file might not exist or be inaccessible
			t.Logf("FtraceEnabled check failed (expected on some systems): %v", err)
		}
	})
}

// Test LockdownMode String method
func TestLockdownMode_String(t *testing.T) {
	tests := []struct {
		name     string
		lockdown LockdownMode
		expected string
	}{
		{"None", NONE, "none"},
		{"Integrity", INTEGRITY, "integrity"},
		{"Confidentiality", CONFIDENTIALITY, "confidentiality"},
		{"Unknown", LockdownMode(999), ""}, // Unknown value should return empty string
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.lockdown.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test Lockdown function
func TestLockdown(t *testing.T) {
	t.Run("real system call", func(t *testing.T) {
		// Test the actual function - this will check the real system
		result, err := Lockdown()

		// We can't predict the result, but it should not panic
		if err == nil {
			assert.IsType(t, NONE, result)
			t.Logf("System lockdown: %v", result)
		} else {
			// On some systems the lockdown file might not exist
			t.Logf("Lockdown check failed (expected on some systems): %v", err)
		}
	})
}
