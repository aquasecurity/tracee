package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

// LEGACY: Tests for legacy threat conversion functions.
// These tests will be removed once the new EventDetector framework replaces the legacy signature system.

func TestGetThreat_WithSeverity(t *testing.T) {
	t.Parallel()

	metadata := map[string]interface{}{
		"Severity":      3,
		"Category":      "Defense Evasion",
		"external_id":   "T1055",
		"Technique":     "Process Injection",
		"signatureName": "ProcessInjectionDetector",
		"custom_field":  "custom_value",
	}

	threat := getThreat("Malicious process injection detected", metadata)

	require.NotNil(t, threat)
	assert.Equal(t, "Malicious process injection detected", threat.Description)
	assert.Equal(t, pb.Severity_HIGH, threat.Severity)
	assert.Equal(t, "ProcessInjectionDetector", threat.Name)
	assert.Equal(t, "Defense Evasion", threat.Mitre.Tactic.Name)
	assert.Equal(t, "T1055", threat.Mitre.Technique.Id)
	assert.Equal(t, "Process Injection", threat.Mitre.Technique.Name)
	assert.Equal(t, "custom_value", threat.Properties["custom_field"])
}

func TestGetThreat_WithoutSeverity(t *testing.T) {
	t.Parallel()

	metadata := map[string]interface{}{
		"Category": "Defense Evasion",
	}

	threat := getThreat("Some description", metadata)

	assert.Nil(t, threat, "Threat should be nil when Severity is missing")
}

func TestGetThreat_NilMetadata(t *testing.T) {
	t.Parallel()

	threat := getThreat("Some description", nil)

	assert.Nil(t, threat, "Threat should be nil when metadata is nil")
}

func TestGetThreat_MinimalMetadata(t *testing.T) {
	t.Parallel()

	metadata := map[string]interface{}{
		"Severity": 1,
	}

	threat := getThreat("Minimal threat", metadata)

	require.NotNil(t, threat)
	assert.Equal(t, "Minimal threat", threat.Description)
	assert.Equal(t, pb.Severity_LOW, threat.Severity)
	assert.Empty(t, threat.Name)
	require.NotNil(t, threat.Mitre)
	require.NotNil(t, threat.Mitre.Tactic)
	assert.Empty(t, threat.Mitre.Tactic.Name)
	require.NotNil(t, threat.Mitre.Technique)
	assert.Empty(t, threat.Mitre.Technique.Id)
	assert.Empty(t, threat.Mitre.Technique.Name)
	assert.Empty(t, threat.Properties)
}

func TestGetThreat_AllSeverityLevels(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		severity         int
		expectedSeverity pb.Severity
	}{
		{"INFO", 0, pb.Severity_INFO},
		{"LOW", 1, pb.Severity_LOW},
		{"MEDIUM", 2, pb.Severity_MEDIUM},
		{"HIGH", 3, pb.Severity_HIGH},
		{"CRITICAL", 4, pb.Severity_CRITICAL},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := map[string]interface{}{
				"Severity": tc.severity,
			}

			threat := getThreat("Test threat", metadata)

			require.NotNil(t, threat)
			assert.Equal(t, tc.expectedSeverity, threat.Severity)
		})
	}
}

func TestGetThreat_InvalidSeverity(t *testing.T) {
	t.Parallel()

	metadata := map[string]interface{}{
		"Severity": 99, // Invalid severity value
	}

	threat := getThreat("Test threat", metadata)

	require.NotNil(t, threat)
	// Invalid severity should default to INFO
	assert.Equal(t, pb.Severity_INFO, threat.Severity)
}

func TestGetThreat_PropertiesExtraction(t *testing.T) {
	t.Parallel()

	metadata := map[string]interface{}{
		"Severity":      2,
		"Category":      "Defense Evasion",   // Should be excluded from properties
		"external_id":   "T1055",             // Should be excluded from properties
		"Technique":     "Process Injection", // Should be excluded from properties
		"signatureName": "TestDetector",      // Should be excluded from properties
		"prop1":         "value1",
		"prop2":         42,
		"prop3":         true,
	}

	threat := getThreat("Test threat", metadata)

	require.NotNil(t, threat)
	assert.Len(t, threat.Properties, 3)
	assert.Equal(t, "value1", threat.Properties["prop1"])
	assert.Equal(t, "42", threat.Properties["prop2"])   // Converted to string
	assert.Equal(t, "true", threat.Properties["prop3"]) // Converted to string
}

func TestGetSeverity_ValidValues(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		severity         int
		expectedSeverity pb.Severity
	}{
		{"INFO", 0, pb.Severity_INFO},
		{"LOW", 1, pb.Severity_LOW},
		{"MEDIUM", 2, pb.Severity_MEDIUM},
		{"HIGH", 3, pb.Severity_HIGH},
		{"CRITICAL", 4, pb.Severity_CRITICAL},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := map[string]interface{}{
				"Severity": tc.severity,
			}

			result := getSeverity(metadata)
			assert.Equal(t, tc.expectedSeverity, result)
		})
	}
}

func TestGetSeverity_MissingSeverity(t *testing.T) {
	t.Parallel()

	metadata := map[string]interface{}{
		"Category": "Defense Evasion",
	}

	result := getSeverity(metadata)

	// Should default to INFO when severity is missing
	assert.Equal(t, pb.Severity_INFO, result)
}

func TestGetSeverity_InvalidSeverity(t *testing.T) {
	t.Parallel()

	metadata := map[string]interface{}{
		"Severity": 99,
	}

	result := getSeverity(metadata)

	// Should default to INFO for invalid severity values
	assert.Equal(t, pb.Severity_INFO, result)
}

func TestGetSeverity_WrongType(t *testing.T) {
	t.Parallel()

	metadata := map[string]interface{}{
		"Severity": "high", // Wrong type - should be int
	}

	result := getSeverity(metadata)

	// Should default to INFO when severity is wrong type
	assert.Equal(t, pb.Severity_INFO, result)
}
