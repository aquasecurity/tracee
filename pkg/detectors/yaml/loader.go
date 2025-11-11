package yaml

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

// LoaderError represents an error that occurred while loading a YAML detector
type LoaderError struct {
	FilePath string
	Err      error
}

// Error implements the error interface
func (e *LoaderError) Error() string {
	return fmt.Sprintf("%s: %v", e.FilePath, e.Err)
}

// Unwrap returns the underlying error
func (e *LoaderError) Unwrap() error {
	return e.Err
}

// LoadFromDirectory scans a directory for YAML detector files and loads them
// Returns successfully loaded detectors and a slice of errors for failed files
// Errors are non-fatal - the function continues processing other files
func LoadFromDirectory(dir string) ([]detection.EventDetector, []error) {
	detectors := make([]detection.EventDetector, 0)
	loaderErrors := make([]error, 0)

	// Check if directory exists
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Directory doesn't exist - not an error, just return empty results
			return detectors, nil
		}
		loaderErrors = append(loaderErrors, &LoaderError{
			FilePath: dir,
			Err:      fmt.Errorf("failed to stat directory: %w", err),
		})
		return detectors, loaderErrors
	}

	if !info.IsDir() {
		loaderErrors = append(loaderErrors, &LoaderError{
			FilePath: dir,
			Err:      errors.New("path is not a directory"),
		})
		return detectors, loaderErrors
	}

	// Read directory contents
	entries, err := os.ReadDir(dir)
	if err != nil {
		loaderErrors = append(loaderErrors, &LoaderError{
			FilePath: dir,
			Err:      fmt.Errorf("failed to read directory: %w", err),
		})
		return detectors, loaderErrors
	}

	// Process each file
	for _, entry := range entries {
		// Skip directories
		if entry.IsDir() {
			continue
		}

		// Only process .yaml and .yml files
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		filePath := filepath.Join(dir, name)

		// Load the detector
		detector, err := LoadFromFile(filePath)
		if err != nil {
			loaderErrors = append(loaderErrors, &LoaderError{
				FilePath: filePath,
				Err:      err,
			})
			continue
		}

		detectors = append(detectors, detector)
	}

	return detectors, loaderErrors
}

// LoadFromDirectories loads detectors from multiple directories
// Returns all successfully loaded detectors and all errors encountered
func LoadFromDirectories(dirs []string) ([]detection.EventDetector, []error) {
	allDetectors := make([]detection.EventDetector, 0)
	allErrors := make([]error, 0)

	for _, dir := range dirs {
		detectors, loaderErrors := LoadFromDirectory(dir)
		allDetectors = append(allDetectors, detectors...)
		allErrors = append(allErrors, loaderErrors...)
	}

	return allDetectors, allErrors
}

// GetDefaultSearchPaths returns the default directories to search for YAML detectors
func GetDefaultSearchPaths() []string {
	return []string{
		"/etc/tracee/detectors",
	}
}

// LoadFromDefaultPaths loads detectors from default search paths
func LoadFromDefaultPaths() ([]detection.EventDetector, []error) {
	return LoadFromDirectories(GetDefaultSearchPaths())
}
