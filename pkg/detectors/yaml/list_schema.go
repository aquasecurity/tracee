package yaml

// Supported list types
const (
	ListTypeString = "string_list"
)

// ListDefinition defines a named list that can be referenced in CEL expressions
type ListDefinition struct {
	Name   string   `yaml:"name"`   // Variable name in CEL (e.g., "SHELL_BINARIES")
	Type   string   `yaml:"type"`   // "string_list" (currently only string lists supported)
	Values []string `yaml:"values"` // The list values
}
