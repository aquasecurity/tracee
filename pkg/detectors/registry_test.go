package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/pkg/events"
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

func TestIsTraceeVersionCompatible(t *testing.T) {
	tests := []struct {
		name           string
		requirements   detection.DetectorRequirements
		currentVersion string
		wantCompatible bool
		wantError      bool
	}{
		{
			name:           "no constraints - always compatible",
			requirements:   detection.DetectorRequirements{},
			currentVersion: "0.20.0",
			wantCompatible: true,
			wantError:      false,
		},
		{
			name: "min version met",
			requirements: detection.DetectorRequirements{
				MinTraceeVersion: &v1beta1.Version{Major: 0, Minor: 20, Patch: 0},
			},
			currentVersion: "0.20.0",
			wantCompatible: true,
		},
		{
			name: "min version not met",
			requirements: detection.DetectorRequirements{
				MinTraceeVersion: &v1beta1.Version{Major: 0, Minor: 21, Patch: 0},
			},
			currentVersion: "0.20.0",
			wantCompatible: false,
		},
		{
			name: "max version not reached (exclusive)",
			requirements: detection.DetectorRequirements{
				MaxTraceeVersion: &v1beta1.Version{Major: 0, Minor: 21, Patch: 0},
			},
			currentVersion: "0.20.0",
			wantCompatible: true,
		},
		{
			name: "max version reached (exclusive)",
			requirements: detection.DetectorRequirements{
				MaxTraceeVersion: &v1beta1.Version{Major: 0, Minor: 20, Patch: 0},
			},
			currentVersion: "0.20.0",
			wantCompatible: false,
		},
		{
			name: "version in range",
			requirements: detection.DetectorRequirements{
				MinTraceeVersion: &v1beta1.Version{Major: 0, Minor: 19, Patch: 0},
				MaxTraceeVersion: &v1beta1.Version{Major: 0, Minor: 21, Patch: 0},
			},
			currentVersion: "0.20.0",
			wantCompatible: true,
		},
		{
			name:           "dev version - allow by default",
			requirements:   detection.DetectorRequirements{},
			currentVersion: "0.20.0-dev",
			wantCompatible: true,
		},
		{
			name: "version with v prefix",
			requirements: detection.DetectorRequirements{
				MinTraceeVersion: &v1beta1.Version{Major: 0, Minor: 20, Patch: 0},
			},
			currentVersion: "v0.20.0",
			wantCompatible: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compatible, err := isTraceeVersionCompatible(tt.requirements, tt.currentVersion)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantCompatible, compatible)
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name string
		a    *v1beta1.Version
		b    *v1beta1.Version
		want int
	}{
		{"equal", &v1beta1.Version{Major: 0, Minor: 20, Patch: 0}, &v1beta1.Version{Major: 0, Minor: 20, Patch: 0}, 0},
		{"major less", &v1beta1.Version{Major: 0, Minor: 20, Patch: 0}, &v1beta1.Version{Major: 1, Minor: 0, Patch: 0}, -1},
		{"major greater", &v1beta1.Version{Major: 1, Minor: 0, Patch: 0}, &v1beta1.Version{Major: 0, Minor: 20, Patch: 0}, 1},
		{"minor less", &v1beta1.Version{Major: 0, Minor: 19, Patch: 0}, &v1beta1.Version{Major: 0, Minor: 20, Patch: 0}, -1},
		{"minor greater", &v1beta1.Version{Major: 0, Minor: 21, Patch: 0}, &v1beta1.Version{Major: 0, Minor: 20, Patch: 0}, 1},
		{"patch less", &v1beta1.Version{Major: 0, Minor: 20, Patch: 0}, &v1beta1.Version{Major: 0, Minor: 20, Patch: 1}, -1},
		{"patch greater", &v1beta1.Version{Major: 0, Minor: 20, Patch: 2}, &v1beta1.Version{Major: 0, Minor: 20, Patch: 1}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareVersions(tt.a, tt.b)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestParseTraceeVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    *v1beta1.Version
		wantErr bool
	}{
		{"basic", "0.20.0", &v1beta1.Version{Major: 0, Minor: 20, Patch: 0}, false},
		{"with v prefix", "v0.20.0", &v1beta1.Version{Major: 0, Minor: 20, Patch: 0}, false},
		{"with dev suffix", "0.20.0-dev", &v1beta1.Version{Major: 0, Minor: 20, Patch: 0}, false},
		{"with rc suffix", "0.21.0-rc1", &v1beta1.Version{Major: 0, Minor: 21, Patch: 0}, false},
		{"invalid - too few parts", "0.20", nil, true},
		{"invalid - non-numeric", "a.b.c", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseTraceeVersion(tt.version)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

func TestCompareEventVersions(t *testing.T) {
	tests := []struct {
		name string
		a    events.Version
		b    *v1beta1.Version
		want int
	}{
		{"equal", events.NewVersion(1, 2, 3), &v1beta1.Version{Major: 1, Minor: 2, Patch: 3}, 0},
		{"major less", events.NewVersion(0, 5, 0), &v1beta1.Version{Major: 1, Minor: 0, Patch: 0}, -1},
		{"major greater", events.NewVersion(2, 0, 0), &v1beta1.Version{Major: 1, Minor: 5, Patch: 0}, 1},
		{"minor less", events.NewVersion(1, 1, 0), &v1beta1.Version{Major: 1, Minor: 2, Patch: 0}, -1},
		{"minor greater", events.NewVersion(1, 3, 0), &v1beta1.Version{Major: 1, Minor: 2, Patch: 0}, 1},
		{"patch less", events.NewVersion(1, 2, 1), &v1beta1.Version{Major: 1, Minor: 2, Patch: 2}, -1},
		{"patch greater", events.NewVersion(1, 2, 4), &v1beta1.Version{Major: 1, Minor: 2, Patch: 3}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareEventVersions(tt.a, tt.b)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestIsEventVersionCompatible(t *testing.T) {
	tests := []struct {
		name         string
		eventVersion events.Version
		requirement  detection.EventRequirement
		wantCompat   bool
	}{
		{
			name:         "no constraints - always compatible",
			eventVersion: events.NewVersion(1, 2, 3),
			requirement:  detection.EventRequirement{},
			wantCompat:   true,
		},
		{
			name:         "min version - compatible",
			eventVersion: events.NewVersion(1, 5, 0),
			requirement: detection.EventRequirement{
				MinVersion: &v1beta1.Version{Major: 1, Minor: 2, Patch: 0},
			},
			wantCompat: true,
		},
		{
			name:         "min version - equal (inclusive)",
			eventVersion: events.NewVersion(1, 2, 0),
			requirement: detection.EventRequirement{
				MinVersion: &v1beta1.Version{Major: 1, Minor: 2, Patch: 0},
			},
			wantCompat: true,
		},
		{
			name:         "min version - incompatible",
			eventVersion: events.NewVersion(1, 1, 0),
			requirement: detection.EventRequirement{
				MinVersion: &v1beta1.Version{Major: 1, Minor: 2, Patch: 0},
			},
			wantCompat: false,
		},
		{
			name:         "max version - compatible",
			eventVersion: events.NewVersion(1, 5, 0),
			requirement: detection.EventRequirement{
				MaxVersion: &v1beta1.Version{Major: 2, Minor: 0, Patch: 0},
			},
			wantCompat: true,
		},
		{
			name:         "max version - equal (exclusive)",
			eventVersion: events.NewVersion(2, 0, 0),
			requirement: detection.EventRequirement{
				MaxVersion: &v1beta1.Version{Major: 2, Minor: 0, Patch: 0},
			},
			wantCompat: false,
		},
		{
			name:         "max version - incompatible",
			eventVersion: events.NewVersion(2, 1, 0),
			requirement: detection.EventRequirement{
				MaxVersion: &v1beta1.Version{Major: 2, Minor: 0, Patch: 0},
			},
			wantCompat: false,
		},
		{
			name:         "min and max - compatible",
			eventVersion: events.NewVersion(1, 5, 0),
			requirement: detection.EventRequirement{
				MinVersion: &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
				MaxVersion: &v1beta1.Version{Major: 2, Minor: 0, Patch: 0},
			},
			wantCompat: true,
		},
		{
			name:         "min and max - below min",
			eventVersion: events.NewVersion(0, 9, 0),
			requirement: detection.EventRequirement{
				MinVersion: &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
				MaxVersion: &v1beta1.Version{Major: 2, Minor: 0, Patch: 0},
			},
			wantCompat: false,
		},
		{
			name:         "min and max - above max",
			eventVersion: events.NewVersion(2, 1, 0),
			requirement: detection.EventRequirement{
				MinVersion: &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
				MaxVersion: &v1beta1.Version{Major: 2, Minor: 0, Patch: 0},
			},
			wantCompat: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compat, err := isEventVersionCompatible(tt.eventVersion, tt.requirement)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantCompat, compat)
		})
	}
}
