package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func TestIsArchitectureSupported(t *testing.T) {
	tests := []struct {
		name         string
		requirements detection.DetectorRequirements
		systemArch   string
		expected     bool
	}{
		{
			name: "no architecture requirement - all supported",
			requirements: detection.DetectorRequirements{
				Architectures: []string{},
			},
			systemArch: "amd64",
			expected:   true,
		},
		{
			name: "nil architectures - all supported",
			requirements: detection.DetectorRequirements{
				Architectures: nil,
			},
			systemArch: "arm64",
			expected:   true,
		},
		{
			name: "matching architecture - amd64",
			requirements: detection.DetectorRequirements{
				Architectures: []string{"amd64"},
			},
			systemArch: "amd64",
			expected:   true,
		},
		{
			name: "matching architecture - arm64",
			requirements: detection.DetectorRequirements{
				Architectures: []string{"arm64"},
			},
			systemArch: "arm64",
			expected:   true,
		},
		{
			name: "non-matching architecture",
			requirements: detection.DetectorRequirements{
				Architectures: []string{"amd64"},
			},
			systemArch: "arm64",
			expected:   false,
		},
		{
			name: "multiple architectures - first matches",
			requirements: detection.DetectorRequirements{
				Architectures: []string{"amd64", "arm64"},
			},
			systemArch: "amd64",
			expected:   true,
		},
		{
			name: "multiple architectures - second matches",
			requirements: detection.DetectorRequirements{
				Architectures: []string{"amd64", "arm64"},
			},
			systemArch: "arm64",
			expected:   true,
		},
		{
			name: "multiple architectures - none match",
			requirements: detection.DetectorRequirements{
				Architectures: []string{"amd64", "arm64"},
			},
			systemArch: "386",
			expected:   false,
		},
		{
			name: "case sensitive - different case",
			requirements: detection.DetectorRequirements{
				Architectures: []string{"AMD64"},
			},
			systemArch: "amd64",
			expected:   false, // Case sensitive
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isArchitectureSupported(tt.requirements, tt.systemArch)
			assert.Equal(t, tt.expected, result, "isArchitectureSupported returned unexpected result")
		})
	}
}
