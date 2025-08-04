package probes

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/utils/environment"
)

// mockOSInfo implements OSInfoProvider for testing
type mockOSInfo struct {
	kernelRelease string
	osReleaseID   environment.OSReleaseID
}

func newMockOSInfo(kernelRelease, osReleaseIDStr string) *mockOSInfo {
	var osReleaseID environment.OSReleaseID
	switch strings.ToLower(osReleaseIDStr) {
	case "ubuntu":
		osReleaseID = environment.UBUNTU
	case "centos":
		osReleaseID = environment.CENTOS
	case "debian":
		osReleaseID = environment.DEBIAN
	case "rhel":
		osReleaseID = environment.RHEL
	default:
		osReleaseID = 0 // Default/undefined OS release ID
	}

	return &mockOSInfo{
		kernelRelease: kernelRelease,
		osReleaseID:   osReleaseID,
	}
}

func (m *mockOSInfo) GetOSReleaseID() environment.OSReleaseID {
	return m.osReleaseID
}

func (m *mockOSInfo) CompareOSBaseKernelRelease(version string) (environment.KernelVersionComparison, error) {
	return environment.CompareKernelRelease(m.kernelRelease, version)
}

func TestKernelVersionRequirement_Basic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		distro           string
		minKernelVersion string
		maxKernelVersion string
		currentKernel    string
		currentDistro    string
		expectedResult   bool
		expectedError    bool
	}{
		{
			name:             "no restrictions - always compatible",
			distro:           "",
			minKernelVersion: "",
			maxKernelVersion: "",
			currentKernel:    "5.10.0",
			currentDistro:    "ubuntu",
			expectedResult:   true,
			expectedError:    false,
		},
		{
			name:             "minimum version requirement - compatible",
			distro:           "",
			minKernelVersion: "5.0.0",
			maxKernelVersion: "",
			currentKernel:    "5.10.0",
			currentDistro:    "ubuntu",
			expectedResult:   true,
			expectedError:    false,
		},
		{
			name:             "minimum version requirement - incompatible",
			distro:           "",
			minKernelVersion: "5.15.0",
			maxKernelVersion: "",
			currentKernel:    "5.10.0",
			currentDistro:    "ubuntu",
			expectedResult:   false,
			expectedError:    false,
		},
		{
			name:             "maximum version requirement - compatible",
			distro:           "",
			minKernelVersion: "",
			maxKernelVersion: "5.15.0",
			currentKernel:    "5.10.0",
			currentDistro:    "ubuntu",
			expectedResult:   true,
			expectedError:    false,
		},
		{
			name:             "maximum version requirement - incompatible",
			distro:           "",
			minKernelVersion: "",
			maxKernelVersion: "5.5.0",
			currentKernel:    "5.10.0",
			currentDistro:    "ubuntu",
			expectedResult:   false,
			expectedError:    false,
		},
		{
			name:             "distro specific - matching distro, compatible version",
			distro:           "ubuntu",
			minKernelVersion: "5.0.0",
			maxKernelVersion: "",
			currentKernel:    "5.10.0",
			currentDistro:    "ubuntu",
			expectedResult:   true,
			expectedError:    false,
		},
		{
			name:             "distro specific - non-matching distro, ignored version check",
			distro:           "centos",
			minKernelVersion: "5.15.0",
			maxKernelVersion: "",
			currentKernel:    "5.10.0",
			currentDistro:    "ubuntu",
			expectedResult:   true,
			expectedError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create kernel version requirement
			req := NewKernelVersionRequirement(tt.distro, tt.minKernelVersion, tt.maxKernelVersion)

			// Verify constructor worked correctly
			assert.Equal(t, tt.distro, req.distro)
			assert.Equal(t, tt.minKernelVersion, req.minKernelVersion)
			assert.Equal(t, tt.maxKernelVersion, req.maxKernelVersion)

			// Create test OSInfo
			osInfo := newMockOSInfo(tt.currentKernel, tt.currentDistro)

			// Test the IsCompatible method
			result, err := req.IsCompatible(osInfo)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result,
					"Expected %v for kernel %s (distro: %s) with requirement (distro: %s, min: %s, max: %s)",
					tt.expectedResult, tt.currentKernel, tt.currentDistro, tt.distro, tt.minKernelVersion, tt.maxKernelVersion)
			}
		})
	}
}

// scenario represents a test scenario for kernel version compatibility
type scenario struct {
	kernelVersion string
	distro        string
	expected      bool
}

func TestKernelVersionRequirement_RealWorldScenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		requirement *KernelVersionRequirement
		scenarios   []scenario
	}{
		{
			name:        "Ubuntu LTS minimum kernel 5.4.0",
			requirement: NewKernelVersionRequirement("ubuntu", "5.4.0", ""),
			scenarios: []scenario{
				{"5.4.0-74-generic", "ubuntu", true},
				{"5.11.0-31-generic", "ubuntu", true},
				{"4.15.0-76-generic", "ubuntu", false},
				{"5.4.0-74-generic", "debian", true}, // Different distro, requirement ignored
			},
		},
		{
			name:        "Feature deprecated after kernel 5.14",
			requirement: NewKernelVersionRequirement("", "", "5.14.0"),
			scenarios: []scenario{
				{"5.13.0", "ubuntu", true},
				{"5.14.0", "ubuntu", true},
				{"5.15.0", "ubuntu", false},
				{"6.0.0", "ubuntu", false},
			},
		},
		{
			name:        "CentOS kernel range",
			requirement: NewKernelVersionRequirement("centos", "4.18.0", "5.10.0"),
			scenarios: []scenario{
				{"4.18.0-305.el8", "centos", true},
				{"4.20.0", "centos", true},
				{"5.10.0", "centos", true},
				{"4.15.0", "centos", false},
				{"5.15.0", "centos", false},
				{"4.15.0", "ubuntu", true}, // Different distro, requirement ignored
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			for _, scenario := range tt.scenarios {
				t.Run(scenario.kernelVersion+"_"+scenario.distro, func(t *testing.T) {
					osInfo := newMockOSInfo(scenario.kernelVersion, scenario.distro)

					result, err := tt.requirement.IsCompatible(osInfo)
					require.NoError(t, err)
					assert.Equal(t, scenario.expected, result,
						"Kernel %s on %s should be %v for requirement (distro: %s, min: %s, max: %s)",
						scenario.kernelVersion, scenario.distro, scenario.expected,
						tt.requirement.distro, tt.requirement.minKernelVersion, tt.requirement.maxKernelVersion)
				})
			}
		})
	}
}

func TestProbeCompatibility_Basic(t *testing.T) {
	t.Parallel()

	// Test ProbeCompatibility constructor and basic functionality
	req1 := NewKernelVersionRequirement("", "5.0.0", "")
	req2 := NewKernelVersionRequirement("ubuntu", "", "6.0.0")

	tests := []struct {
		name         string
		probe        Handle
		requirements []ProbeRequirement
	}{
		{
			name:         "no requirements",
			probe:        1, // Mock handle
			requirements: []ProbeRequirement{},
		},
		{
			name:         "single requirement",
			probe:        1,
			requirements: []ProbeRequirement{req1},
		},
		{
			name:         "multiple requirements",
			probe:        1,
			requirements: []ProbeRequirement{req1, req2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			compatibility := NewProbeCompatibility(tt.probe, tt.requirements)

			assert.NotNil(t, compatibility)
			assert.Equal(t, tt.probe, compatibility.probe)
			assert.Equal(t, len(tt.requirements), len(compatibility.requirements))

			// Verify each requirement is stored correctly
			for i, req := range tt.requirements {
				assert.Equal(t, req, compatibility.requirements[i])
			}
		})
	}
}

func TestProbeCompatibility_MultipleRequirements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		requirements   []ProbeRequirement
		currentKernel  string
		currentDistro  string
		expectedResult bool
	}{
		{
			name:           "no requirements - always compatible",
			requirements:   []ProbeRequirement{},
			currentKernel:  "5.10.0",
			currentDistro:  "ubuntu",
			expectedResult: true,
		},
		{
			name: "all requirements compatible",
			requirements: []ProbeRequirement{
				NewKernelVersionRequirement("", "5.0.0", ""),
				NewKernelVersionRequirement("", "", "6.0.0"),
			},
			currentKernel:  "5.10.0",
			currentDistro:  "ubuntu",
			expectedResult: true,
		},
		{
			name: "one requirement incompatible",
			requirements: []ProbeRequirement{
				NewKernelVersionRequirement("", "5.0.0", ""),
				NewKernelVersionRequirement("", "", "5.5.0"), // Max 5.5.0, current is 5.10.0
			},
			currentKernel:  "5.10.0",
			currentDistro:  "ubuntu",
			expectedResult: false,
		},
		{
			name: "distro-specific requirements",
			requirements: []ProbeRequirement{
				NewKernelVersionRequirement("ubuntu", "5.4.0", ""),
				NewKernelVersionRequirement("centos", "4.18.0", ""),
			},
			currentKernel:  "5.10.0",
			currentDistro:  "ubuntu",
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			compatibility := NewProbeCompatibility(1, tt.requirements)
			osInfo := newMockOSInfo(tt.currentKernel, tt.currentDistro)

			result, err := compatibility.IsCompatible(osInfo)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestKernelVersionRequirement_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		distro           string
		minKernelVersion string
		maxKernelVersion string
		currentKernel    string
		currentDistro    string
		expectedResult   bool
	}{
		{
			name:             "equal to minimum version",
			distro:           "",
			minKernelVersion: "5.10.0",
			maxKernelVersion: "",
			currentKernel:    "5.10.0",
			currentDistro:    "ubuntu",
			expectedResult:   true,
		},
		{
			name:             "equal to maximum version",
			distro:           "",
			minKernelVersion: "",
			maxKernelVersion: "5.10.0",
			currentKernel:    "5.10.0",
			currentDistro:    "ubuntu",
			expectedResult:   true,
		},
		{
			name:             "complex ubuntu kernel version",
			distro:           "",
			minKernelVersion: "5.4.0",
			maxKernelVersion: "",
			currentKernel:    "5.4.0-74-generic",
			currentDistro:    "ubuntu",
			expectedResult:   true,
		},
		{
			name:             "complex centos kernel version",
			distro:           "centos",
			minKernelVersion: "4.18.0",
			maxKernelVersion: "",
			currentKernel:    "4.18.0-305.el8",
			currentDistro:    "centos",
			expectedResult:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := NewKernelVersionRequirement(tt.distro, tt.minKernelVersion, tt.maxKernelVersion)
			osInfo := newMockOSInfo(tt.currentKernel, tt.currentDistro)

			result, err := req.IsCompatible(osInfo)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
