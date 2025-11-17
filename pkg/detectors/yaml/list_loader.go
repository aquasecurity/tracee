package yaml

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/tracee/common/errfmt"
)

var (
	// validListNameRegex ensures list names are uppercase snake_case
	validListNameRegex = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// LoadListsFromDirectory loads all list definition files from {dir}/lists/ subdirectory
// Returns a map of list name -> list values
func LoadListsFromDirectory(dir string) (map[string][]string, error) {
	listsDir := filepath.Join(dir, "lists")

	// Check if lists directory exists
	if _, err := os.Stat(listsDir); os.IsNotExist(err) {
		// No lists directory is fine - lists are optional
		return make(map[string][]string), nil
	}

	lists := make(map[string][]string)

	// Walk the lists directory
	err := filepath.Walk(listsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only process .yaml and .yml files
		if !strings.HasSuffix(info.Name(), ".yaml") && !strings.HasSuffix(info.Name(), ".yml") {
			return nil
		}

		// Load and parse the list file
		listDef, err := loadListFile(path)
		if err != nil {
			return errfmt.Errorf("failed to load list file %s: %v", path, err)
		}

		// Validate list name
		if err := validateListName(listDef.Name); err != nil {
			return errfmt.Errorf("invalid list name in %s: %v", path, err)
		}

		// Check for duplicate list names
		if _, exists := lists[listDef.Name]; exists {
			return errfmt.Errorf("duplicate list name %s in %s", listDef.Name, path)
		}

		// Validate list type
		if listDef.Type != ListTypeString {
			return errfmt.Errorf("unsupported list type %s in %s (only %s is supported)", listDef.Type, path, ListTypeString)
		}

		// Validate list has values
		if len(listDef.Values) == 0 {
			return errfmt.Errorf("list %s in %s has no values", listDef.Name, path)
		}

		lists[listDef.Name] = listDef.Values
		return nil
	})

	if err != nil {
		return nil, err
	}

	return lists, nil
}

// loadListFile reads and parses a single list definition file
func loadListFile(filePath string) (*ListDefinition, error) {
	// Check file size
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	if fileInfo.Size() > MaxYAMLFileSize {
		return nil, errfmt.Errorf("list file too large: %d bytes (max: %d bytes)", fileInfo.Size(), MaxYAMLFileSize)
	}

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	// Parse YAML
	var listDef ListDefinition
	if err := yaml.Unmarshal(data, &listDef); err != nil {
		return nil, errfmt.Errorf("failed to parse YAML: %v", err)
	}

	return &listDef, nil
}

// validateListName ensures list names follow uppercase snake_case convention
func validateListName(name string) error {
	if name == "" {
		return errfmt.Errorf("list name cannot be empty")
	}

	if !validListNameRegex.MatchString(name) {
		return errfmt.Errorf("list name '%s' must be uppercase snake_case (e.g., SHELL_BINARIES)", name)
	}

	return nil
}
