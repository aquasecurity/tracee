package yaml

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFromFile(t *testing.T) {
	t.Run("valid threat detector", func(t *testing.T) {
		detector, err := LoadFromFile("testdata/valid_threat.yaml", nil)
		require.NoError(t, err)
		require.NotNil(t, detector)

		def := detector.GetDefinition()
		assert.Equal(t, "TRC-TEST-001", def.ID)
		assert.Equal(t, "test_threat_detection", def.ProducedEvent.Name)
	})

	t.Run("invalid file returns error", func(t *testing.T) {
		_, err := LoadFromFile("testdata/invalid_syntax.yaml", nil)
		assert.Error(t, err)
	})

	t.Run("missing file returns error", func(t *testing.T) {
		_, err := LoadFromFile("testdata/doesnotexist.yaml", nil)
		assert.Error(t, err)
	})
}

func TestLoadFromDirectory(t *testing.T) {
	t.Run("load testdata directory", func(t *testing.T) {
		detectors, errors := LoadFromDirectory("testdata")

		// Should load valid detectors
		assert.NotEmpty(t, detectors)

		// Should have errors for invalid files
		assert.NotEmpty(t, errors)

		// Check we got the valid ones
		ids := make(map[string]bool)
		for _, d := range detectors {
			ids[d.GetDefinition().ID] = true
		}

		assert.True(t, ids["TRC-TEST-001"], "Should load valid_threat.yaml")
		assert.True(t, ids["DRV-TEST-001"], "Should load valid_derived.yaml")
		assert.True(t, ids["MIN-TEST-001"], "Should load minimal.yaml")
	})

	t.Run("non-existent directory", func(t *testing.T) {
		detectors, errors := LoadFromDirectory("testdata/doesnotexist")
		assert.Empty(t, detectors)
		assert.Empty(t, errors) // Non-existent directory is not an error
	})

	t.Run("file instead of directory", func(t *testing.T) {
		detectors, errors := LoadFromDirectory("testdata/valid_threat.yaml")
		assert.Empty(t, detectors)
		assert.NotEmpty(t, errors)
	})
}

func TestLoadFromDirectories(t *testing.T) {
	t.Run("multiple directories", func(t *testing.T) {
		dirs := []string{"testdata", "testdata"} // Same dir twice
		detectors, errors := LoadFromDirectories(dirs)

		// Should load detectors (may have duplicates from same dir twice)
		assert.NotEmpty(t, detectors)

		// Should have some errors from invalid files
		assert.NotEmpty(t, errors)
	})

	t.Run("empty list", func(t *testing.T) {
		detectors, errors := LoadFromDirectories([]string{})
		assert.Empty(t, detectors)
		assert.Empty(t, errors)
	})
}

func TestGetDefaultSearchPaths(t *testing.T) {
	paths := GetDefaultSearchPaths()
	assert.NotEmpty(t, paths)
	assert.Contains(t, paths, "/etc/tracee/detectors")
}
