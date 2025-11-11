package yaml

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func TestParseFile(t *testing.T) {
	tests := []struct {
		name      string
		file      string
		wantError bool
	}{
		{
			name:      "valid threat detector",
			file:      "testdata/valid_threat.yaml",
			wantError: false,
		},
		{
			name:      "valid derived event",
			file:      "testdata/valid_derived.yaml",
			wantError: false,
		},
		{
			name:      "minimal detector",
			file:      "testdata/minimal.yaml",
			wantError: false,
		},
		{
			name:      "invalid syntax",
			file:      "testdata/invalid_syntax.yaml",
			wantError: true,
		},
		{
			name:      "non-existent file",
			file:      "testdata/doesnotexist.yaml",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseFile(tt.file)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, spec)
			}
		})
	}
}

func TestToDetectorDefinition(t *testing.T) {
	t.Run("valid threat detector", func(t *testing.T) {
		spec, err := ParseFile("testdata/valid_threat.yaml")
		require.NoError(t, err)

		def, err := ToDetectorDefinition(spec)
		require.NoError(t, err)

		assert.Equal(t, "TRC-TEST-001", def.ID)
		assert.Equal(t, "test_threat_detection", def.ProducedEvent.Name)
		assert.Equal(t, uint64(1), def.ProducedEvent.Version.Major)
		assert.NotNil(t, def.ThreatMetadata)
		assert.Equal(t, v1beta1.Severity_HIGH, def.ThreatMetadata.Severity)
		assert.True(t, def.AutoPopulate.Threat)
		assert.True(t, def.AutoPopulate.DetectedFrom)
		assert.Len(t, def.Requirements.Events, 1)
	})

	t.Run("valid derived event", func(t *testing.T) {
		spec, err := ParseFile("testdata/valid_derived.yaml")
		require.NoError(t, err)

		def, err := ToDetectorDefinition(spec)
		require.NoError(t, err)

		assert.Equal(t, "DRV-TEST-001", def.ID)
		assert.Nil(t, def.ThreatMetadata) // Derived events have no threat
		assert.False(t, def.AutoPopulate.Threat)
		assert.True(t, def.AutoPopulate.DetectedFrom)
		assert.Len(t, def.ProducedEvent.Fields, 1)
	})
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		wantMajor uint64
		wantMinor uint64
		wantPatch uint64
		wantError bool
	}{
		{
			name:      "major.minor.patch",
			version:   "1.2.3",
			wantMajor: 1,
			wantMinor: 2,
			wantPatch: 3,
		},
		{
			name:      "major.minor",
			version:   "2.5",
			wantMajor: 2,
			wantMinor: 5,
			wantPatch: 0,
		},
		{
			name:      "empty string",
			version:   "",
			wantError: true,
		},
		{
			name:      "invalid format",
			version:   "1",
			wantError: true,
		},
		{
			name:      "non-numeric",
			version:   "a.b.c",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver, err := parseVersion(tt.version)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantMajor, ver.Major)
				assert.Equal(t, tt.wantMinor, ver.Minor)
				assert.Equal(t, tt.wantPatch, ver.Patch)
			}
		})
	}
}

func TestParseDependencyType(t *testing.T) {
	tests := []struct {
		name      string
		dep       string
		want      detection.DependencyType
		wantError bool
	}{
		{
			name: "required",
			dep:  "required",
			want: detection.DependencyRequired,
		},
		{
			name: "optional",
			dep:  "optional",
			want: detection.DependencyOptional,
		},
		{
			name: "required uppercase",
			dep:  "REQUIRED",
			want: detection.DependencyRequired,
		},
		{
			name:      "invalid",
			dep:       "invalid",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep, err := parseDependencyType(tt.dep)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, dep)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name      string
		severity  string
		want      v1beta1.Severity
		wantError bool
	}{
		{
			name:     "low",
			severity: "low",
			want:     v1beta1.Severity_LOW,
		},
		{
			name:     "medium",
			severity: "medium",
			want:     v1beta1.Severity_MEDIUM,
		},
		{
			name:     "high",
			severity: "high",
			want:     v1beta1.Severity_HIGH,
		},
		{
			name:     "critical",
			severity: "critical",
			want:     v1beta1.Severity_CRITICAL,
		},
		{
			name:     "uppercase",
			severity: "HIGH",
			want:     v1beta1.Severity_HIGH,
		},
		{
			name:      "invalid",
			severity:  "invalid",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sev, err := parseSeverity(tt.severity)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, sev)
			}
		})
	}
}

func TestParseAndConvert(t *testing.T) {
	t.Run("full workflow with valid file", func(t *testing.T) {
		filePath := "testdata/valid_threat.yaml"
		def, spec, err := ParseAndConvert(filePath)
		require.NoError(t, err)
		assert.NotNil(t, def)
		assert.NotNil(t, spec)
		assert.Equal(t, "TRC-TEST-001", def.ID)
		assert.Equal(t, "test_threat_detection", def.ProducedEvent.Name)
	})

	t.Run("invalid file returns error", func(t *testing.T) {
		filePath := "testdata/invalid_syntax.yaml"
		_, _, err := ParseAndConvert(filePath)
		assert.Error(t, err)
	})
}

func TestParseProducedEvent(t *testing.T) {
	t.Run("with fields", func(t *testing.T) {
		spec := ProducedEventSpec{
			Name:        "test_event",
			Version:     "1.0.0",
			Description: "Test event",
			Tags:        []string{"test"},
			Fields: []EventFieldSpec{
				{Name: "field1", Type: "string", Description: "Field 1"},
			},
		}

		event, err := parseProducedEvent(spec)
		require.NoError(t, err)
		assert.Equal(t, "test_event", event.Name)
		assert.Len(t, event.Fields, 1)
		assert.Equal(t, "field1", event.Fields[0].Name)
	})

	t.Run("without fields", func(t *testing.T) {
		spec := ProducedEventSpec{
			Name:    "test_event",
			Version: "1.0.0",
		}

		event, err := parseProducedEvent(spec)
		require.NoError(t, err)
		assert.Equal(t, "test_event", event.Name)
		assert.Empty(t, event.Fields)
	})
}
