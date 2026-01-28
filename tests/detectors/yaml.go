package detectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	yamldetectors "github.com/aquasecurity/tracee/pkg/detectors/yaml"
	"github.com/aquasecurity/tracee/pkg/events"
)

// LoadYAMLDetectorFromString parses YAML content and returns a detector
func LoadYAMLDetectorFromString(t *testing.T, yamlContent string) detection.EventDetector {
	// Create a temporary file
	tmpFile := CreateTempYAMLDetector(t, yamlContent)
	defer func() {
		_ = os.Remove(tmpFile)
	}()

	// Load the detector
	detector, err := yamldetectors.LoadFromFile(tmpFile, nil)
	require.NoError(t, err, "Failed to load YAML detector")

	return detector
}

// LoadYAMLDetectorFromFile loads a YAML detector from a file
func LoadYAMLDetectorFromFile(t *testing.T, filePath string) detection.EventDetector {
	detector, err := yamldetectors.LoadFromFile(filePath, nil)
	require.NoError(t, err, "Failed to load YAML detector from %s", filePath)

	return detector
}

// NewYAMLTestHarness creates a harness with a YAML detector already loaded
// selectedEvents are the kernel/base events that the YAML detector will consume
func NewYAMLTestHarness(t *testing.T, yamlContent string, selectedEvents ...events.ID) *TestHarness {
	// Create harness
	harness := NewTestHarness(t, selectedEvents...)

	// Load and register YAML detector
	detector := LoadYAMLDetectorFromString(t, yamlContent)
	err := harness.RegisterDetector(detector)
	require.NoError(t, err, "Failed to register YAML detector")

	return harness
}

// CreateTempYAMLDetector creates a temporary YAML file for testing
// Returns the path to the temporary file
func CreateTempYAMLDetector(t *testing.T, yamlContent string) string {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create temp file
	tmpFile := filepath.Join(tmpDir, "detector.yaml")
	err := os.WriteFile(tmpFile, []byte(yamlContent), 0644)
	require.NoError(t, err, "Failed to create temp YAML file")

	return tmpFile
}
