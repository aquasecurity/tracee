package probes

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/environment"
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

// mockMapTypeSupportChecker creates a mock function for testing map type support
func mockMapTypeSupportChecker(supportedTypes map[bpf.MapType]bool, shouldError bool, errorMessage string) MapTypeSupportChecker {
	return func(mapType bpf.MapType) (bool, error) {
		if shouldError {
			message := errorMessage
			if message == "" {
				message = "mock error for testing"
			}
			return false, errors.New(message)
		}
		if supportedTypes == nil {
			return false, errors.New("no BPF support configuration provided for testing")
		}
		supported, exists := supportedTypes[mapType]
		if !exists {
			return false, nil // Unknown map types default to not supported (realistic behavior)
		}
		return supported, nil
	}
}

// mockProgramTypeChecker creates a mock function for testing program type support
func mockProgramTypeChecker(supportedTypes map[bpf.BPFProgType]bool, shouldError bool, errorMessage string) ProgramTypeSupportChecker {
	return func(progType bpf.BPFProgType) (bool, error) {
		if shouldError {
			message := errorMessage
			if message == "" {
				message = "mock error for testing"
			}
			return false, errors.New(message)
		}
		if supportedTypes == nil {
			return false, errors.New("no BPF program type support configuration provided for testing")
		}
		supported, exists := supportedTypes[progType]
		if !exists {
			return false, nil // Unknown program types default to not supported (realistic behavior)
		}
		return supported, nil
	}
}

// mockHelperSupportChecker creates a mock function for testing helper function support
func mockHelperSupportChecker(supportedHelpers map[string]bool, shouldError bool, errorMessage string) HelperSupportChecker {
	return func(progType bpf.BPFProgType, funcID bpf.BPFFunc) (bool, error) {
		if shouldError {
			message := errorMessage
			if message == "" {
				message = "mock error for testing"
			}
			return false, errors.New(message)
		}
		if supportedHelpers == nil {
			return false, errors.New("no BPF helper support configuration provided for testing")
		}
		// Create a unique key for the progType + funcID combination
		key := fmt.Sprintf("%d:%d", progType, funcID)
		supported, exists := supportedHelpers[key]
		if !exists {
			return false, nil // Unknown helpers default to not supported (realistic behavior)
		}
		return supported, nil
	}
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
		requirements []ProbeRequirement
	}{
		{
			name:         "no requirements",
			requirements: []ProbeRequirement{},
		},
		{
			name:         "single requirement",
			requirements: []ProbeRequirement{req1},
		},
		{
			name:         "multiple requirements",
			requirements: []ProbeRequirement{req1, req2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			compatibility := NewProbeCompatibility(tt.requirements...)

			assert.NotNil(t, compatibility)
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

			compatibility := NewProbeCompatibility(tt.requirements...)
			osInfo := newMockOSInfo(tt.currentKernel, tt.currentDistro)

			result, err := compatibility.isCompatible(osInfo)
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

func TestBPFMapTypeRequirement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		mapType        bpf.MapType
		supportedTypes map[bpf.MapType]bool
		shouldError    bool
		errorMessage   string
		expectedResult bool
		expectedError  bool
	}{
		{
			name:           "hash map type supported",
			mapType:        bpf.MapTypeHash,
			supportedTypes: map[bpf.MapType]bool{bpf.MapTypeHash: true},
			expectedResult: true,
			expectedError:  false,
		},
		{
			name:           "array map type not supported",
			mapType:        bpf.MapTypeArray,
			supportedTypes: map[bpf.MapType]bool{bpf.MapTypeArray: false},
			expectedResult: false,
			expectedError:  false,
		},
		{
			name:           "error checking map type support",
			mapType:        bpf.MapTypeHash,
			shouldError:    true,
			errorMessage:   "failed to check BPF map type support",
			expectedResult: false,
			expectedError:  true,
		},
		{
			name:           "unknown map type not in supportedTypes map",
			mapType:        bpf.MapType(999),                            // Unknown type
			supportedTypes: map[bpf.MapType]bool{bpf.MapTypeHash: true}, // 999 not included
			expectedResult: false,
			expectedError:  false,
		},
		{
			name:    "nil supportedTypes map should error",
			mapType: bpf.MapTypeHash,
			// supportedTypes: nil - should trigger error
			expectedResult: false,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create mock environment provider
			envProvider := newMockOSInfo("5.4.0", "ubuntu")

			// Create mock checker function
			mockChecker := mockMapTypeSupportChecker(tt.supportedTypes, tt.shouldError, tt.errorMessage)

			// Create BPF map type requirement with mock checker
			req := NewBPFMapTypeRequirementWithChecker(tt.mapType, mockChecker)
			result, err := req.IsCompatible(envProvider)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestBpfProgramRequirement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		progType       bpf.BPFProgType
		supportedTypes map[bpf.BPFProgType]bool
		shouldError    bool
		errorMessage   string
		expectedResult bool
		expectedError  bool
	}{
		{
			name:           "program type supported",
			progType:       bpf.BPFProgTypeKprobe,
			supportedTypes: map[bpf.BPFProgType]bool{bpf.BPFProgTypeKprobe: true},
			expectedResult: true,
			expectedError:  false,
		},
		{
			name:           "program type not supported",
			progType:       bpf.BPFProgTypeTracepoint,
			supportedTypes: map[bpf.BPFProgType]bool{bpf.BPFProgTypeTracepoint: false},
			expectedResult: false,
			expectedError:  false,
		},
		{
			name:           "error checking program type support",
			progType:       bpf.BPFProgTypeKprobe,
			shouldError:    true,
			errorMessage:   "failed to check BPF program type support",
			expectedResult: false,
			expectedError:  true,
		},
		{
			name:           "unknown program type defaults to not supported",
			progType:       bpf.BPFProgType(999), // Unknown type
			supportedTypes: map[bpf.BPFProgType]bool{bpf.BPFProgTypeKprobe: true},
			expectedResult: false,
			expectedError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create mock environment provider
			envProvider := newMockOSInfo("5.4.0", "ubuntu")

			// Create mock checker function
			mockChecker := mockProgramTypeChecker(tt.supportedTypes, tt.shouldError, tt.errorMessage)

			// Create BPF program type requirement with mock checker
			req := NewBpfProgramRequirementWithChecker(tt.progType, mockChecker)
			result, err := req.IsCompatible(envProvider)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestBPFHelperRequirement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		progType        bpf.BPFProgType
		funcID          bpf.BPFFunc
		supportedHelper bool
		shouldError     bool
		errorMessage    string
		expectedResult  bool
		expectedError   bool
	}{
		{
			name:            "helper function supported",
			progType:        bpf.BPFProgTypeKprobe,
			funcID:          bpf.BPFFuncMapLookupElem,
			supportedHelper: true,
			expectedResult:  true,
			expectedError:   false,
		},
		{
			name:            "helper function not supported",
			progType:        bpf.BPFProgTypeKprobe,
			funcID:          bpf.BPFFuncMapLookupElem,
			supportedHelper: false,
			expectedResult:  false,
			expectedError:   false,
		},
		{
			name:           "error checking helper function support",
			progType:       bpf.BPFProgTypeKprobe,
			funcID:         bpf.BPFFuncMapLookupElem,
			shouldError:    true,
			errorMessage:   "failed to check BPF helper function support",
			expectedResult: false,
			expectedError:  true,
		},
		{
			name:            "unknown helper function defaults to not supported",
			progType:        bpf.BPFProgType(999), // Unknown program type
			funcID:          bpf.BPFFunc(999),     // Unknown function ID
			supportedHelper: false,                // Not in map, should default to false
			expectedResult:  false,
			expectedError:   false,
		},
		{
			name:     "nil supportedHelpers map should error",
			progType: bpf.BPFProgTypeKprobe,
			funcID:   bpf.BPFFuncMapLookupElem,
			// supportedHelpers: nil - should trigger error
			expectedResult: false,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create mock environment provider
			envProvider := newMockOSInfo("5.4.0", "ubuntu")

			// Create supported helpers map for this test
			var supportedHelpers map[string]bool
			if !tt.shouldError && tt.name != "nil supportedHelpers map should error" {
				key := fmt.Sprintf("%d:%d", tt.progType, tt.funcID)
				supportedHelpers = map[string]bool{key: tt.supportedHelper}
			}

			// Create mock checker function
			mockChecker := mockHelperSupportChecker(supportedHelpers, tt.shouldError, tt.errorMessage)

			// Create BPF helper requirement with mock checker
			req := NewBPFHelperRequirementWithChecker(tt.progType, tt.funcID, mockChecker)
			result, err := req.IsCompatible(envProvider)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestBPFHelperRequirement_Constructor(t *testing.T) {
	t.Parallel()

	progType := bpf.BPFProgTypeKprobe
	funcID := bpf.BPFFuncMapLookupElem

	// Test basic constructor
	req := NewBPFHelperRequirement(progType, funcID)
	assert.NotNil(t, req)
	assert.Equal(t, progType, req.progType)
	assert.Equal(t, funcID, req.funcID)
	assert.NotNil(t, req.checker)

	// Test constructor with custom checker
	customChecker := func(pt bpf.BPFProgType, fid bpf.BPFFunc) (bool, error) {
		return true, nil
	}
	reqWithChecker := NewBPFHelperRequirementWithChecker(progType, funcID, customChecker)
	assert.NotNil(t, reqWithChecker)
	assert.Equal(t, progType, reqWithChecker.progType)
	assert.Equal(t, funcID, reqWithChecker.funcID)
	assert.NotNil(t, reqWithChecker.checker)
}

func TestProbeCompatibility_WithBpfProgramRequirement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		kernelRequirement    *KernelVersionRequirement
		programRequirement   *BpfProgramRequirement
		currentKernel        string
		currentDistro        string
		programTypeSupported bool
		expectedResult       bool
	}{
		{
			name:                 "both kernel and program requirements compatible",
			kernelRequirement:    NewKernelVersionRequirement("", "5.0.0", ""),
			programRequirement:   nil, // will be set in test with mock
			currentKernel:        "5.10.0",
			currentDistro:        "ubuntu",
			programTypeSupported: true,
			expectedResult:       true,
		},
		{
			name:                 "kernel compatible but program type not supported",
			kernelRequirement:    NewKernelVersionRequirement("", "5.0.0", ""),
			programRequirement:   nil, // will be set in test with mock
			currentKernel:        "5.10.0",
			currentDistro:        "ubuntu",
			programTypeSupported: false,
			expectedResult:       false,
		},
		{
			name:                 "kernel not compatible but program type supported",
			kernelRequirement:    NewKernelVersionRequirement("", "5.15.0", ""),
			programRequirement:   nil, // will be set in test with mock
			currentKernel:        "5.10.0",
			currentDistro:        "ubuntu",
			programTypeSupported: true,
			expectedResult:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create mock BPF program support checker
			supportedTypes := map[bpf.BPFProgType]bool{bpf.BPFProgTypeKprobe: tt.programTypeSupported}
			mockChecker := mockProgramTypeChecker(supportedTypes, false, "")

			// Create program requirement with mock checker
			tt.programRequirement = NewBpfProgramRequirementWithChecker(bpf.BPFProgTypeKprobe, mockChecker)

			// Create probe compatibility with both requirements
			compatibility := NewProbeCompatibility(tt.kernelRequirement, tt.programRequirement)
			envProvider := newMockOSInfo(tt.currentKernel, tt.currentDistro)

			result, err := compatibility.isCompatible(envProvider)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
