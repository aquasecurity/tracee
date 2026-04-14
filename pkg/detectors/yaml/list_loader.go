package yaml

import (
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/tracee/common/errfmt"
)

var (
	// validListNameRegex ensures list names are uppercase snake_case
	validListNameRegex = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// loadListFile reads and parses a single list definition file
func loadListFile(filePath string) (*ListDefinition, error) {
	// Use Lstat to avoid following symlinks and to reject non-regular files
	// (FIFOs, device files, sockets). os.ReadFile on a FIFO blocks indefinitely.
	fileInfo, err := os.Lstat(filePath)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	if !fileInfo.Mode().IsRegular() {
		return nil, errfmt.Errorf("not a regular file: %s", filePath)
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

	// Validate type field is present and correct
	if listDef.Type == "" {
		return nil, errfmt.Errorf("missing required field 'type'")
	}

	normalized := strings.TrimSpace(strings.ToLower(listDef.Type))
	if normalized != ListTypeString {
		return nil, errfmt.Errorf("invalid type '%s', must be 'string_list'", listDef.Type)
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
