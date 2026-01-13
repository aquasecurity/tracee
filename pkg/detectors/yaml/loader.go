package yaml

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

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

// ListEntry represents a shared list with its source location
type ListEntry struct {
	Name      string
	Values    []string
	SourceDir string
}

// LoadResult contains the results of loading from a directory
type LoadResult struct {
	Detectors []detection.EventDetector
	Lists     []ListEntry
	Errors    []error
}

// LoadFromDirectory scans a directory for YAML detector and list files and loads them
// Returns successfully loaded detectors, lists, and a slice of errors for failed files
// Errors are non-fatal - the function continues processing other files
func LoadFromDirectory(dir string) LoadResult {
	result := LoadResult{
		Detectors: make([]detection.EventDetector, 0),
		Lists:     make([]ListEntry, 0),
		Errors:    make([]error, 0),
	}

	// Check if directory exists
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Directory doesn't exist - not an error, just return empty results
			return result
		}
		result.Errors = append(result.Errors, &LoaderError{
			FilePath: dir,
			Err:      fmt.Errorf("failed to stat directory: %w", err),
		})
		return result
	}

	if !info.IsDir() {
		result.Errors = append(result.Errors, &LoaderError{
			FilePath: dir,
			Err:      errors.New("path is not a directory"),
		})
		return result
	}

	// Read directory (flat - no subdirectories)
	entries, err := os.ReadDir(dir)
	if err != nil {
		result.Errors = append(result.Errors, &LoaderError{
			FilePath: dir,
			Err:      fmt.Errorf("failed to read directory: %w", err),
		})
		return result
	}

	// PASS 1: Categorize all YAML files by type (read each file ONCE)
	listPaths := make([]string, 0)
	detectorPaths := make([]string, 0)

	for _, entry := range entries {
		// Skip subdirectories (flat structure only)
		if entry.IsDir() {
			continue
		}

		// Skip non-YAML files
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		path := filepath.Join(dir, name)

		// Peek at type field
		fileType, err := peekFileType(path)
		if err != nil {
			result.Errors = append(result.Errors, &LoaderError{
				FilePath: path,
				Err:      fmt.Errorf("failed to read type field: %w", err),
			})
			continue
		}

		// Route by type
		switch fileType {
		case ListTypeString:
			listPaths = append(listPaths, path)
		case TypeDetector:
			detectorPaths = append(detectorPaths, path)
		case "":
			result.Errors = append(result.Errors, &LoaderError{
				FilePath: path,
				Err:      errors.New("missing required field 'type'"),
			})
		default:
			result.Errors = append(result.Errors, &LoaderError{
				FilePath: path,
				Err:      fmt.Errorf("invalid type '%s', must be 'detector' or 'string_list'", fileType),
			})
		}
	}

	// PASS 2: Load all lists
	// listsMap is used for detector validation (lists are scoped to directory)
	listsMap := make(map[string][]string)
	for _, path := range listPaths {
		listDef, err := loadListFile(path)
		if err != nil {
			result.Errors = append(result.Errors, &LoaderError{
				FilePath: path,
				Err:      err,
			})
			continue
		}

		// Validate list name
		if err := validateListName(listDef.Name); err != nil {
			result.Errors = append(result.Errors, &LoaderError{
				FilePath: path,
				Err:      err,
			})
			continue
		}

		// Check for duplicates within directory
		if _, exists := listsMap[listDef.Name]; exists {
			result.Errors = append(result.Errors, &LoaderError{
				FilePath: path,
				Err:      fmt.Errorf("duplicate list name '%s'", listDef.Name),
			})
			continue
		}

		listsMap[listDef.Name] = listDef.Values
		result.Lists = append(result.Lists, ListEntry{
			Name:      listDef.Name,
			Values:    listDef.Values,
			SourceDir: dir,
		})
	}

	// PASS 3: Load all detectors with lists context
	for _, path := range detectorPaths {
		detector, err := LoadFromFile(path, listsMap)
		if err != nil {
			result.Errors = append(result.Errors, err)
			continue
		}

		result.Detectors = append(result.Detectors, detector)
	}

	return result
}

// peekFileType reads just the type field from a YAML file
// Returns empty string if type field is missing
func peekFileType(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	var peek struct {
		Type string `yaml:"type"`
	}

	if err := yaml.Unmarshal(data, &peek); err != nil {
		return "", err
	}

	// Normalize: trim whitespace, lowercase for case-insensitive comparison
	return strings.TrimSpace(strings.ToLower(peek.Type)), nil
}

// LoadFromDirectories loads detectors and lists from multiple directories
// Returns all successfully loaded detectors, all lists with source info, and all errors encountered
func LoadFromDirectories(dirs []string) LoadResult {
	combined := LoadResult{
		Detectors: make([]detection.EventDetector, 0),
		Lists:     make([]ListEntry, 0),
		Errors:    make([]error, 0),
	}

	for _, dir := range dirs {
		result := LoadFromDirectory(dir)
		combined.Detectors = append(combined.Detectors, result.Detectors...)
		combined.Errors = append(combined.Errors, result.Errors...)
		// Lists from each directory are collected separately with source info
		combined.Lists = append(combined.Lists, result.Lists...)
	}

	return combined
}

// GetDefaultSearchPaths returns the default directories to search for YAML detectors
func GetDefaultSearchPaths() []string {
	return []string{
		"/etc/tracee/detectors",
	}
}

// LoadFromDefaultPaths loads detectors and lists from default search paths
func LoadFromDefaultPaths() LoadResult {
	return LoadFromDirectories(GetDefaultSearchPaths())
}
