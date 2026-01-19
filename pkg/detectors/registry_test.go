package detectors

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/digest"
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

func TestRegisterDetector_ScopeFilters(t *testing.T) {
	tests := []struct {
		name        string
		requirement detection.EventRequirement
		expectErr   bool
	}{
		{
			name: "valid scope filter - container",
			requirement: detection.EventRequirement{
				Name:         "execve",
				Dependency:   detection.DependencyRequired,
				ScopeFilters: []string{"container"},
			},
			expectErr: false,
		},
		{
			name: "valid scope filter - container=started",
			requirement: detection.EventRequirement{
				Name:         "execve",
				Dependency:   detection.DependencyRequired,
				ScopeFilters: []string{"container=started"},
			},
			expectErr: false,
		},
		{
			name: "valid scope filter - host",
			requirement: detection.EventRequirement{
				Name:         "execve",
				Dependency:   detection.DependencyRequired,
				ScopeFilters: []string{"host"},
			},
			expectErr: false,
		},
		{
			name: "valid scope filter - pid",
			requirement: detection.EventRequirement{
				Name:         "execve",
				Dependency:   detection.DependencyRequired,
				ScopeFilters: []string{"pid=1"},
			},
			expectErr: false,
		},
		{
			name: "multiple valid scope filters",
			requirement: detection.EventRequirement{
				Name:         "execve",
				Dependency:   detection.DependencyRequired,
				ScopeFilters: []string{"container=started", "pid>100"},
			},
			expectErr: false,
		},
		{
			name: "invalid scope filter - bad syntax",
			requirement: detection.EventRequirement{
				Name:         "execve",
				Dependency:   detection.DependencyRequired,
				ScopeFilters: []string{"invalid_filter==="},
			},
			expectErr: true,
		},
		{
			name: "invalid scope filter - unsupported field",
			requirement: detection.EventRequirement{
				Name:         "execve",
				Dependency:   detection.DependencyRequired,
				ScopeFilters: []string{"nonexistent=value"},
			},
			expectErr: true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pre-register this test's detector event before creating the detector
			testDetectorID := "test_scope_filter_" + tt.name
			mockDetectors := []detection.EventDetector{
				&mockDetector{
					id:        testDetectorID,
					eventName: testDetectorID + "_event",
					requirements: detection.DetectorRequirements{
						Events: []detection.EventRequirement{tt.requirement},
					},
				},
			}
			_, err := CreateEventsFromDetectors(events.StartDetectorID+events.ID(i+100), mockDetectors)
			assert.NoError(t, err, "Failed to pre-register detector event")

			registry := newRegistry(nil, nil) // Pass nil policy manager and enrichment options for test
			detector := &mockDetector{
				id:        testDetectorID,
				eventName: testDetectorID + "_event",
				requirements: detection.DetectorRequirements{
					Events: []detection.EventRequirement{tt.requirement},
				},
			}

			err = registry.RegisterDetector(detector, detection.DetectorParams{})
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRegisterDetector_DataFilters(t *testing.T) {
	tests := []struct {
		name        string
		requirement detection.EventRequirement
		expectErr   bool
	}{
		{
			name: "valid data filter - equal",
			requirement: detection.EventRequirement{
				Name:        "execve",
				Dependency:  detection.DependencyRequired,
				DataFilters: []string{"pathname=/bin/bash"},
			},
			expectErr: false,
		},
		{
			name: "valid data filter - not equal",
			requirement: detection.EventRequirement{
				Name:        "execve",
				Dependency:  detection.DependencyRequired,
				DataFilters: []string{"pathname!=/usr/bin"},
			},
			expectErr: false,
		},
		{
			name: "valid data filter - wildcard",
			requirement: detection.EventRequirement{
				Name:        "execve",
				Dependency:  detection.DependencyRequired,
				DataFilters: []string{"pathname=/usr/bin/python*"},
			},
			expectErr: false,
		},
		{
			name: "multiple valid data filters",
			requirement: detection.EventRequirement{
				Name:        "execve",
				Dependency:  detection.DependencyRequired,
				DataFilters: []string{"pathname=/bin/bash", "pathname!=/tmp/*"},
			},
			expectErr: false,
		},
		{
			name: "invalid data filter - bad syntax",
			requirement: detection.EventRequirement{
				Name:        "execve",
				Dependency:  detection.DependencyRequired,
				DataFilters: []string{"invalid===filter"},
			},
			expectErr: true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pre-register this test's detector event before creating the detector
			testDetectorID := "test_data_filter_" + tt.name
			mockDetectors := []detection.EventDetector{
				&mockDetector{
					id:        testDetectorID,
					eventName: testDetectorID + "_event",
					requirements: detection.DetectorRequirements{
						Events: []detection.EventRequirement{tt.requirement},
					},
				},
			}
			_, err := CreateEventsFromDetectors(events.StartDetectorID+events.ID(i+200), mockDetectors)
			assert.NoError(t, err, "Failed to pre-register detector event")

			registry := newRegistry(nil, nil) // Pass nil policy manager and enrichment options for test
			detector := &mockDetector{
				id:        testDetectorID,
				eventName: testDetectorID + "_event",
				requirements: detection.DetectorRequirements{
					Events: []detection.EventRequirement{tt.requirement},
				},
			}

			err = registry.RegisterDetector(detector, detection.DetectorParams{})
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRegisterDetector_ScopeAndDataFilters(t *testing.T) {
	tests := []struct {
		name        string
		requirement detection.EventRequirement
		expectErr   bool
	}{
		{
			name: "both scope and data filters",
			requirement: detection.EventRequirement{
				Name:         "execve",
				Dependency:   detection.DependencyRequired,
				ScopeFilters: []string{"container=started"},
				DataFilters:  []string{"pathname=/bin/bash"},
			},
			expectErr: false,
		},
		{
			name: "multiple scope and data filters",
			requirement: detection.EventRequirement{
				Name:         "execve",
				Dependency:   detection.DependencyRequired,
				ScopeFilters: []string{"container", "pid>100"},
				DataFilters:  []string{"pathname=/bin/bash", "pathname!=/tmp/*"},
			},
			expectErr: false,
		},
		{
			name: "invalid scope filter with valid data filter",
			requirement: detection.EventRequirement{
				Name:         "execve",
				Dependency:   detection.DependencyRequired,
				ScopeFilters: []string{"invalid==="},
				DataFilters:  []string{"pathname=/bin/bash"},
			},
			expectErr: true,
		},
		{
			name: "valid scope filter with invalid data filter",
			requirement: detection.EventRequirement{
				Name:         "execve",
				Dependency:   detection.DependencyRequired,
				ScopeFilters: []string{"container"},
				DataFilters:  []string{"invalid==="},
			},
			expectErr: true,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pre-register this test's detector event before creating the detector
			testDetectorID := "test_combined_filters_" + tt.name
			mockDetectors := []detection.EventDetector{
				&mockDetector{
					id:        testDetectorID,
					eventName: testDetectorID + "_event",
					requirements: detection.DetectorRequirements{
						Events: []detection.EventRequirement{tt.requirement},
					},
				},
			}
			_, err := CreateEventsFromDetectors(events.StartDetectorID+events.ID(i+300), mockDetectors)
			assert.NoError(t, err, "Failed to pre-register detector event")

			registry := newRegistry(nil, nil) // Pass nil policy manager and enrichment options for test
			detector := &mockDetector{
				id:        testDetectorID,
				eventName: testDetectorID + "_event",
				requirements: detection.DetectorRequirements{
					Events: []detection.EventRequirement{tt.requirement},
				},
			}

			err = registry.RegisterDetector(detector, detection.DetectorParams{})
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// mockDetector is a simple mock for testing
type mockDetector struct {
	id           string
	eventName    string // Unique event name for this detector
	requirements detection.DetectorRequirements
}

func (m *mockDetector) GetDefinition() detection.DetectorDefinition {
	// Use provided event name or default to id + "_event"
	producedEventName := m.eventName
	if producedEventName == "" {
		producedEventName = m.id + "_event"
	}
	return detection.DetectorDefinition{
		ID:           m.id,
		Requirements: m.requirements,
		ProducedEvent: v1beta1.EventDefinition{
			Name: producedEventName,
		},
		AutoPopulate: detection.AutoPopulateFields{},
	}
}

func (m *mockDetector) Init(params detection.DetectorParams) error {
	return nil
}

func (m *mockDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	return nil, nil
}

func (m *mockDetector) Close() error {
	return nil
}

func TestRegistry_EnrichmentValidation(t *testing.T) {
	tests := []struct {
		name        string
		enrichments []detection.EnrichmentRequirement
		enrichOpts  *EnrichmentOptions
		expectErr   bool
		errMsg      string
	}{
		{
			name:        "no enrichments required - should pass",
			enrichments: []detection.EnrichmentRequirement{},
			enrichOpts: &EnrichmentOptions{
				Environment: false,
			},
			expectErr: false,
		},
		{
			name: "enrichment environment required and enabled",
			enrichments: []detection.EnrichmentRequirement{
				{Name: detection.EnrichmentEnvironment, Dependency: detection.DependencyRequired},
			},
			enrichOpts: &EnrichmentOptions{
				Environment: true,
			},
			expectErr: false,
		},
		{
			name: "enrichment environment required but not enabled",
			enrichments: []detection.EnrichmentRequirement{
				{Name: detection.EnrichmentEnvironment, Dependency: detection.DependencyRequired},
			},
			enrichOpts: &EnrichmentOptions{
				Environment: false,
			},
			expectErr: true,
			errMsg:    "requires enrichment \"environment\" which is not enabled",
		},
		{
			name: "enrichment environment optional and not enabled",
			enrichments: []detection.EnrichmentRequirement{
				{Name: detection.EnrichmentEnvironment, Dependency: detection.DependencyOptional},
			},
			enrichOpts: &EnrichmentOptions{
				Environment: false,
			},
			expectErr: false,
		},
		{
			name: "enrichment executable-hash required and enabled",
			enrichments: []detection.EnrichmentRequirement{
				{Name: detection.EnrichmentExecutableHash, Dependency: detection.DependencyRequired},
			},
			enrichOpts: &EnrichmentOptions{
				Environment:  false,
				ExecHashMode: digest.CalcHashesInode,
			},
			expectErr: false,
		},
		{
			name: "enrichment executable-hash required but not enabled",
			enrichments: []detection.EnrichmentRequirement{
				{Name: detection.EnrichmentExecutableHash, Dependency: detection.DependencyRequired},
			},
			enrichOpts: &EnrichmentOptions{
				Environment: false,
			},
			expectErr: true,
			errMsg:    "requires enrichment \"executable-hash\" which is not enabled",
		},
		{
			name: "enrichment executable-hash with specific config - inode mode",
			enrichments: []detection.EnrichmentRequirement{
				{Name: detection.EnrichmentExecutableHash, Dependency: detection.DependencyRequired, Config: detection.ExecutableHashConfigInode},
			},
			enrichOpts: &EnrichmentOptions{
				Environment:  false,
				ExecHashMode: digest.CalcHashesInode,
			},
			expectErr: false,
		},
		{
			name: "enrichment executable-hash with specific config - dev-inode mode",
			enrichments: []detection.EnrichmentRequirement{
				{Name: detection.EnrichmentExecutableHash, Dependency: detection.DependencyRequired, Config: detection.ExecutableHashConfigDevInode},
			},
			enrichOpts: &EnrichmentOptions{
				Environment:  false,
				ExecHashMode: digest.CalcHashesDevInode,
			},
			expectErr: false,
		},
		{
			name: "enrichment executable-hash with specific config - digest-inode mode",
			enrichments: []detection.EnrichmentRequirement{
				{Name: detection.EnrichmentExecutableHash, Dependency: detection.DependencyRequired, Config: detection.ExecutableHashConfigDigestInode},
			},
			enrichOpts: &EnrichmentOptions{
				Environment:  false,
				ExecHashMode: digest.CalcHashesDigestInode,
			},
			expectErr: false,
		},
		{
			name: "enrichment executable-hash mode mismatch - should fail",
			enrichments: []detection.EnrichmentRequirement{
				{Name: detection.EnrichmentExecutableHash, Dependency: detection.DependencyRequired, Config: detection.ExecutableHashConfigDigestInode},
			},
			enrichOpts: &EnrichmentOptions{
				Environment:  false,
				ExecHashMode: digest.CalcHashesInode,
			},
			expectErr: true,
			errMsg:    "requires enrichment \"executable-hash\" with mode \"digest-inode\", but current mode is \"inode\"",
		},
		{
			name: "enrichment executable-hash mode mismatch optional - should not fail",
			enrichments: []detection.EnrichmentRequirement{
				{Name: detection.EnrichmentExecutableHash, Dependency: detection.DependencyOptional, Config: detection.ExecutableHashConfigDigestInode},
			},
			enrichOpts: &EnrichmentOptions{
				Environment:  false,
				ExecHashMode: digest.CalcHashesInode,
			},
			expectErr: false, // Optional dependency, should not fail
		},
		{
			name: "multiple enrichment options - all enabled",
			enrichments: []detection.EnrichmentRequirement{
				{Name: detection.EnrichmentEnvironment, Dependency: detection.DependencyRequired},
				{Name: detection.EnrichmentExecutableHash, Dependency: detection.DependencyRequired},
			},
			enrichOpts: &EnrichmentOptions{
				Environment:  true,
				ExecHashMode: digest.CalcHashesInode,
			},
			expectErr: false,
		},
		{
			name: "enrichment container required and enabled",
			enrichments: []detection.EnrichmentRequirement{
				{Name: "container", Dependency: detection.DependencyRequired},
			},
			enrichOpts: &EnrichmentOptions{
				Container: true,
			},
			expectErr: false,
		},
		{
			name: "enrichment container required but not enabled",
			enrichments: []detection.EnrichmentRequirement{
				{Name: "container", Dependency: detection.DependencyRequired},
			},
			enrichOpts: &EnrichmentOptions{
				Container: false,
			},
			expectErr: true,
			errMsg:    "requires enrichment \"container\" which is not enabled",
		},
		{
			name: "enrichment container optional and not enabled",
			enrichments: []detection.EnrichmentRequirement{
				{Name: "container", Dependency: detection.DependencyOptional},
			},
			enrichOpts: &EnrichmentOptions{
				Container: false,
			},
			expectErr: false,
		},
		{
			name: "mixed enrichment options: container required, environment optional",
			enrichments: []detection.EnrichmentRequirement{
				{Name: detection.EnrichmentContainer, Dependency: detection.DependencyRequired},
				{Name: detection.EnrichmentEnvironment, Dependency: detection.DependencyOptional},
			},
			enrichOpts: &EnrichmentOptions{
				Container:   true,
				Environment: false,
			},
			expectErr: false,
		},
		{
			name: "multiple enrichment options - one missing",
			enrichments: []detection.EnrichmentRequirement{
				{Name: detection.EnrichmentEnvironment, Dependency: detection.DependencyRequired},
				{Name: detection.EnrichmentExecutableHash, Dependency: detection.DependencyRequired},
			},
			enrichOpts: &EnrichmentOptions{
				Environment: true,
			},
			expectErr: true,
			errMsg:    "requires enrichment \"executable-hash\" which is not enabled",
		},
		{
			name: "unknown enrichment",
			enrichments: []detection.EnrichmentRequirement{
				{Name: "unknown-enrichment", Dependency: detection.DependencyRequired},
			},
			enrichOpts: &EnrichmentOptions{
				Environment: false,
			},
			expectErr: true,
			errMsg:    "requires unknown enrichment: unknown-enrichment",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pre-register the detector's produced event with unique ID and name per test
			eventName := fmt.Sprintf("test_event_%d", i)
			mockDetectors := []detection.EventDetector{
				&mockDetector{
					id:        "test-detector",
					eventName: eventName,
				},
			}
			_, err := CreateEventsFromDetectors(events.StartDetectorID+events.ID(i+900), mockDetectors)
			assert.NoError(t, err, "Failed to pre-register detector event")

			// Create registry with nil policy manager and enrichment options
			registry := newRegistry(nil, tt.enrichOpts)

			// Create detector with enrichment requirements
			detector := &mockDetector{
				id:        "test-detector",
				eventName: eventName,
				requirements: detection.DetectorRequirements{
					Events: []detection.EventRequirement{
						{Name: "syscall_table_check"},
					},
					Enrichments: tt.enrichments,
				},
			}

			// Try to register detector
			err = registry.RegisterDetector(detector, detection.DetectorParams{})

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
