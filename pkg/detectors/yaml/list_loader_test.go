package yaml

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadListsFromDirectory_NoListsDir(t *testing.T) {
	// Create temporary directory without lists subdirectory
	tmpDir := t.TempDir()

	lists, err := LoadListsFromDirectory(tmpDir)
	require.NoError(t, err)
	assert.Empty(t, lists, "Should return empty map when lists directory doesn't exist")
}

func TestLoadListsFromDirectory_ValidList(t *testing.T) {
	// Create temporary directory structure
	tmpDir := t.TempDir()
	listsDir := filepath.Join(tmpDir, "lists")
	require.NoError(t, os.Mkdir(listsDir, 0755))

	// Create a valid list file
	listYAML := `name: SHELL_BINARIES
type: string_list
values:
  - /bin/sh
  - /bin/bash
  - /usr/bin/zsh
`
	listFile := filepath.Join(listsDir, "shells.yaml")
	require.NoError(t, os.WriteFile(listFile, []byte(listYAML), 0644))

	lists, err := LoadListsFromDirectory(tmpDir)
	require.NoError(t, err)
	require.Contains(t, lists, "SHELL_BINARIES")
	assert.Equal(t, []string{"/bin/sh", "/bin/bash", "/usr/bin/zsh"}, lists["SHELL_BINARIES"])
}

func TestLoadListsFromDirectory_MultipleLists(t *testing.T) {
	// Create temporary directory structure
	tmpDir := t.TempDir()
	listsDir := filepath.Join(tmpDir, "lists")
	require.NoError(t, os.Mkdir(listsDir, 0755))

	// Create first list
	list1YAML := `name: LIST_ONE
type: string_list
values:
  - value1
  - value2
`
	require.NoError(t, os.WriteFile(filepath.Join(listsDir, "list1.yaml"), []byte(list1YAML), 0644))

	// Create second list
	list2YAML := `name: LIST_TWO
type: string_list
values:
  - value3
  - value4
`
	require.NoError(t, os.WriteFile(filepath.Join(listsDir, "list2.yaml"), []byte(list2YAML), 0644))

	lists, err := LoadListsFromDirectory(tmpDir)
	require.NoError(t, err)
	assert.Len(t, lists, 2)
	assert.Contains(t, lists, "LIST_ONE")
	assert.Contains(t, lists, "LIST_TWO")
}

func TestLoadListsFromDirectory_InvalidName(t *testing.T) {
	tmpDir := t.TempDir()
	listsDir := filepath.Join(tmpDir, "lists")
	require.NoError(t, os.Mkdir(listsDir, 0755))

	// Create list with invalid name (lowercase)
	listYAML := `name: invalid_name
type: string_list
values:
  - value1
`
	listFile := filepath.Join(listsDir, "invalid.yaml")
	require.NoError(t, os.WriteFile(listFile, []byte(listYAML), 0644))

	_, err := LoadListsFromDirectory(tmpDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be uppercase snake_case")
}

func TestLoadListsFromDirectory_DuplicateName(t *testing.T) {
	tmpDir := t.TempDir()
	listsDir := filepath.Join(tmpDir, "lists")
	require.NoError(t, os.Mkdir(listsDir, 0755))

	// Create two lists with the same name
	listYAML := `name: DUPLICATE_LIST
type: string_list
values:
  - value1
`
	require.NoError(t, os.WriteFile(filepath.Join(listsDir, "list1.yaml"), []byte(listYAML), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(listsDir, "list2.yaml"), []byte(listYAML), 0644))

	_, err := LoadListsFromDirectory(tmpDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate list name")
}

func TestLoadListsFromDirectory_UnsupportedType(t *testing.T) {
	tmpDir := t.TempDir()
	listsDir := filepath.Join(tmpDir, "lists")
	require.NoError(t, os.Mkdir(listsDir, 0755))

	// Create list with unsupported type
	listYAML := `name: INVALID_TYPE_LIST
type: int_list
values:
  - value1
`
	listFile := filepath.Join(listsDir, "invalid.yaml")
	require.NoError(t, os.WriteFile(listFile, []byte(listYAML), 0644))

	_, err := LoadListsFromDirectory(tmpDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported list type")
}

func TestLoadListsFromDirectory_EmptyValues(t *testing.T) {
	tmpDir := t.TempDir()
	listsDir := filepath.Join(tmpDir, "lists")
	require.NoError(t, os.Mkdir(listsDir, 0755))

	// Create list with no values
	listYAML := `name: EMPTY_LIST
type: string_list
values: []
`
	listFile := filepath.Join(listsDir, "empty.yaml")
	require.NoError(t, os.WriteFile(listFile, []byte(listYAML), 0644))

	_, err := LoadListsFromDirectory(tmpDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "has no values")
}

func TestLoadListsFromDirectory_FileTooLarge(t *testing.T) {
	tmpDir := t.TempDir()
	listsDir := filepath.Join(tmpDir, "lists")
	require.NoError(t, os.Mkdir(listsDir, 0755))

	// Create a file larger than MaxYAMLFileSize
	listFile := filepath.Join(listsDir, "toolarge.yaml")
	largeContent := make([]byte, MaxYAMLFileSize+1)
	require.NoError(t, os.WriteFile(listFile, largeContent, 0644))

	_, err := LoadListsFromDirectory(tmpDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list file too large")
}

func TestLoadListsFromDirectory_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	listsDir := filepath.Join(tmpDir, "lists")
	require.NoError(t, os.Mkdir(listsDir, 0755))

	// Create invalid YAML
	listFile := filepath.Join(listsDir, "invalid.yaml")
	require.NoError(t, os.WriteFile(listFile, []byte("invalid: yaml: content:"), 0644))

	_, err := LoadListsFromDirectory(tmpDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse YAML")
}

func TestValidateListName(t *testing.T) {
	testCases := []struct {
		name      string
		listName  string
		expectErr bool
	}{
		{"valid uppercase", "SHELL_BINARIES", false},
		{"valid single word", "SHELLS", false},
		{"valid with numbers", "LIST_123", false},
		{"invalid lowercase", "shell_binaries", true},
		{"invalid mixed case", "Shell_Binaries", true},
		{"invalid starts with number", "123_LIST", true},
		{"invalid starts with underscore", "_LIST", true},
		{"invalid empty", "", true},
		{"invalid space", "SHELL BINARIES", true},
		{"invalid dash", "SHELL-BINARIES", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateListName(tc.listName)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
