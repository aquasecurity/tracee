package yaml

import (
	"fmt"
	"runtime"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/errfmt"
)

// Valid root segments for extraction paths
var validExtractionRoots = []string{"data", "workload", "timestamp", "id", "name", "policies"}

// ValidateSpec validates a parsed YAML detector specification
func ValidateSpec(spec *YAMLDetectorSpec, lists map[string][]string, filePath string) error {
	if spec == nil {
		return errfmt.Errorf("spec cannot be nil")
	}

	// Validate required fields
	if spec.ID == "" {
		return errfmt.Errorf("%s: detector ID is required", filePath)
	}

	// Validate produced event
	if err := validateProducedEvent(spec.ProducedEvent, filePath); err != nil {
		return err
	}

	// Validate requirements
	if err := validateRequirements(spec.Requirements, filePath); err != nil {
		return err
	}

	// Validate threat metadata if present
	if spec.Threat != nil {
		if err := validateThreat(spec.Threat, filePath); err != nil {
			return err
		}
	}

	// Validate CEL conditions if present
	if len(spec.Conditions) > 0 {
		if err := validateConditions(spec.Conditions, lists, filePath); err != nil {
			return err
		}
	}

	// Validate output extraction if present
	if spec.Output != nil {
		if err := validateOutput(spec.Output, spec.ProducedEvent.Fields, lists, filePath); err != nil {
			return err
		}
	}

	return nil
}

// validateProducedEvent validates the produced event specification
func validateProducedEvent(spec ProducedEventSpec, filePath string) error {
	if spec.Name == "" {
		return errfmt.Errorf("%s: produced_event.name is required", filePath)
	}

	if spec.Version == "" {
		return errfmt.Errorf("%s: produced_event.version is required", filePath)
	}

	// Validate version format
	if _, err := parseVersion(spec.Version); err != nil {
		return fmt.Errorf("%s: produced_event.version: %w", filePath, err)
	}

	// Validate event fields if present
	if len(spec.Fields) > 0 {
		fieldNames := make(map[string]bool)
		for _, field := range spec.Fields {
			if field.Name == "" {
				return errfmt.Errorf("%s: event field name is required", filePath)
			}
			if field.Type == "" {
				return errfmt.Errorf("%s: event field '%s' type is required", filePath, field.Name)
			}

			// Check for duplicate field names
			if fieldNames[field.Name] {
				return errfmt.Errorf("%s: duplicate field name '%s'", filePath, field.Name)
			}
			fieldNames[field.Name] = true

			// Validate field type
			if !isValidFieldType(field.Type) {
				return errfmt.Errorf("%s: invalid field type '%s' for field '%s': must be one of string, int32, uint32, uint64, bool, bytes", filePath, field.Type, field.Name)
			}
		}
	}

	return nil
}

// validateRequirements validates the requirements specification
func validateRequirements(spec RequirementsSpec, filePath string) error {
	// Validate version constraints
	if spec.MinTraceeVersion != "" {
		if _, err := parseVersion(spec.MinTraceeVersion); err != nil {
			return fmt.Errorf("%s: requirements.min_tracee_version: %w", filePath, err)
		}
	}

	if spec.MaxTraceeVersion != "" {
		if _, err := parseVersion(spec.MaxTraceeVersion); err != nil {
			return fmt.Errorf("%s: requirements.max_tracee_version: %w", filePath, err)
		}
	}

	// Validate min < max if both present
	if spec.MinTraceeVersion != "" && spec.MaxTraceeVersion != "" {
		minVer, _ := parseVersion(spec.MinTraceeVersion)
		maxVer, _ := parseVersion(spec.MaxTraceeVersion)
		if !versionLessThan(minVer, maxVer) {
			return errfmt.Errorf("%s: min_tracee_version must be less than max_tracee_version", filePath)
		}
	}

	// Validate architectures
	if len(spec.Architectures) > 0 {
		for _, arch := range spec.Architectures {
			if !isValidArchitecture(arch) {
				return errfmt.Errorf("%s: invalid architecture '%s': must be valid GOARCH value (e.g., amd64, arm64)", filePath, arch)
			}
		}
	}

	// Validate event requirements
	if len(spec.Events) == 0 {
		return errfmt.Errorf("%s: at least one event requirement is required", filePath)
	}

	eventNames := make(map[string]bool)
	for _, event := range spec.Events {
		if err := validateEventRequirement(event, filePath); err != nil {
			return err
		}

		// Check for duplicate event names
		if eventNames[event.Name] {
			return errfmt.Errorf("%s: duplicate event requirement '%s'", filePath, event.Name)
		}
		eventNames[event.Name] = true
	}

	// Validate enrichment requirements
	if len(spec.Enrichments) > 0 {
		enrichNames := make(map[string]bool)
		for _, enrich := range spec.Enrichments {
			if err := validateEnrichmentRequirement(enrich, filePath); err != nil {
				return err
			}

			// Check for duplicate enrichment names
			if enrichNames[enrich.Name] {
				return errfmt.Errorf("%s: duplicate enrichment requirement '%s'", filePath, enrich.Name)
			}
			enrichNames[enrich.Name] = true
		}
	}

	return nil
}

// validateEventRequirement validates an event requirement
func validateEventRequirement(spec EventRequirementSpec, filePath string) error {
	if spec.Name == "" {
		return errfmt.Errorf("%s: event requirement name is required", filePath)
	}

	// Validate dependency type if specified
	if spec.Dependency != "" {
		if _, err := parseDependencyType(spec.Dependency); err != nil {
			return fmt.Errorf("%s: event '%s': %w", filePath, spec.Name, err)
		}
	}

	// Validate version constraints
	if spec.MinVersion != "" {
		if _, err := parseVersion(spec.MinVersion); err != nil {
			return fmt.Errorf("%s: event '%s' min_version: %w", filePath, spec.Name, err)
		}
	}

	if spec.MaxVersion != "" {
		if _, err := parseVersion(spec.MaxVersion); err != nil {
			return fmt.Errorf("%s: event '%s' max_version: %w", filePath, spec.Name, err)
		}
	}

	// Validate min < max if both present
	if spec.MinVersion != "" && spec.MaxVersion != "" {
		minVer, _ := parseVersion(spec.MinVersion)
		maxVer, _ := parseVersion(spec.MaxVersion)
		if !versionLessThan(minVer, maxVer) {
			return errfmt.Errorf("%s: event '%s': min_version must be less than max_version", filePath, spec.Name)
		}
	}

	// Note: Filter syntax validation would require access to policy filter parser
	// This is deferred to runtime validation when filters are actually applied

	return nil
}

// validateEnrichmentRequirement validates an enrichment requirement
func validateEnrichmentRequirement(spec EnrichmentRequirementSpec, filePath string) error {
	if spec.Name == "" {
		return errfmt.Errorf("%s: enrichment requirement name is required", filePath)
	}

	// Validate dependency type if specified
	if spec.Dependency != "" {
		if _, err := parseDependencyType(spec.Dependency); err != nil {
			return fmt.Errorf("%s: enrichment '%s': %w", filePath, spec.Name, err)
		}
	}

	// Validate known enrichment names
	if !isValidEnrichmentName(spec.Name) {
		return errfmt.Errorf("%s: unknown enrichment '%s': must be one of exec-env, exec-hash, container", filePath, spec.Name)
	}

	return nil
}

// validateThreat validates threat metadata
func validateThreat(spec *ThreatSpec, filePath string) error {
	if spec.Description == "" {
		return errfmt.Errorf("%s: threat.description is required", filePath)
	}

	if spec.Severity == "" {
		return errfmt.Errorf("%s: threat.severity is required", filePath)
	}

	// Validate severity value
	if _, err := parseSeverity(spec.Severity); err != nil {
		return fmt.Errorf("%s: threat.severity: %w", filePath, err)
	}

	return nil
}

// validateOutput validates the output specification and checks against declared fields
func validateOutput(spec *OutputSpec, declaredFields []EventFieldSpec, lists map[string][]string, filePath string) error {
	if len(spec.Fields) == 0 {
		return nil // Empty output is valid
	}

	// Create CEL environment once for all field validations
	env, err := createCELEnvironment(lists, nil)
	if err != nil {
		return fmt.Errorf("%s: failed to create CEL environment: %w", filePath, err)
	}

	extractedNames := make(map[string]bool)
	for i, field := range spec.Fields {
		if field.Name == "" {
			return errfmt.Errorf("%s: output field %d name is required", filePath, i)
		}

		// Expression is required
		if field.Expression == "" {
			return errfmt.Errorf("%s: output field '%s' expression is required", filePath, field.Name)
		}

		// Validate CEL expression
		_, err = CompileExpression(env, field.Expression)
		if err != nil {
			return fmt.Errorf("%s: output field '%s' has invalid CEL expression '%s': %w", filePath, field.Name, field.Expression, err)
		}

		// Check for duplicate field names
		if extractedNames[field.Name] {
			return errfmt.Errorf("%s: duplicate output field name '%s'", filePath, field.Name)
		}
		extractedNames[field.Name] = true
	}

	// If event fields are declared, validate that extracted fields match
	if len(declaredFields) > 0 {
		declaredMap := make(map[string]EventFieldSpec)
		for _, f := range declaredFields {
			declaredMap[f.Name] = f
		}

		for _, extracted := range spec.Fields {
			declared, exists := declaredMap[extracted.Name]
			if !exists && !extracted.Optional {
				return errfmt.Errorf("%s: extracted field '%s' not declared in produced_event.fields", filePath, extracted.Name)
			}

			// Type checking would require knowing the CEL expression return type
			// This is deferred to runtime validation
			_ = declared
		}
	}

	return nil
}

// isValidFieldType checks if a field type is valid
func isValidFieldType(t string) bool {
	validTypes := []string{"string", "int32", "uint32", "uint64", "bool", "bytes"}
	for _, valid := range validTypes {
		if t == valid {
			return true
		}
	}
	return false
}

// isValidArchitecture checks if an architecture string is valid
func isValidArchitecture(arch string) bool {
	// List of valid GOARCH values
	validArchs := []string{
		"386", "amd64", "arm", "arm64", "loong64", "mips", "mips64",
		"mips64le", "mipsle", "ppc64", "ppc64le", "riscv64", "s390x", "wasm",
	}

	for _, valid := range validArchs {
		if arch == valid {
			return true
		}
	}

	// Also check current runtime architecture as a safety check
	if arch == runtime.GOARCH {
		return true
	}

	return false
}

// isValidEnrichmentName checks if an enrichment name is known
func isValidEnrichmentName(name string) bool {
	validEnrichments := []string{
		detection.EnrichmentExecEnv,
		detection.EnrichmentExecHash,
		detection.EnrichmentContainer,
	}
	for _, valid := range validEnrichments {
		if name == valid {
			return true
		}
	}
	return false
}

// versionLessThan compares two versions and returns true if v1 < v2
func versionLessThan(v1, v2 *v1beta1.Version) bool {
	if v1.Major != v2.Major {
		return v1.Major < v2.Major
	}
	if v1.Minor != v2.Minor {
		return v1.Minor < v2.Minor
	}
	return v1.Patch < v2.Patch
}

// ValidateDefinition validates a converted DetectorDefinition
// This is called after parsing and conversion to ensure the final definition is valid
func ValidateDefinition(def *detection.DetectorDefinition) error {
	if def.ID == "" {
		return errfmt.Errorf("detector ID is required")
	}

	if def.ProducedEvent.Name == "" {
		return errfmt.Errorf("produced event name is required")
	}

	if len(def.Requirements.Events) == 0 {
		return errfmt.Errorf("at least one event requirement is required")
	}

	return nil
}

// ParseAndValidate is a convenience function that parses and validates a YAML file
func ParseAndValidate(filePath string, lists map[string][]string) (*detection.DetectorDefinition, *YAMLDetectorSpec, error) {
	spec, err := ParseFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse file: %w", err)
	}

	if err := ValidateSpec(spec, lists, filePath); err != nil {
		return nil, spec, fmt.Errorf("validation failed: %w", err)
	}

	def, err := ToDetectorDefinition(spec)
	if err != nil {
		return nil, spec, fmt.Errorf("failed to convert to detector definition: %w", err)
	}

	if err := ValidateDefinition(def); err != nil {
		return nil, spec, fmt.Errorf("definition validation failed: %w", err)
	}

	return def, spec, nil
}

// validateConditions validates CEL condition expressions
func validateConditions(conditions []string, lists map[string][]string, filePath string) error {
	if len(conditions) == 0 {
		return nil
	}

	// Create CEL environment for validation with lists
	env, err := createCELEnvironment(lists, nil)
	if err != nil {
		return fmt.Errorf("%s: failed to create CEL environment: %w", filePath, err)
	}

	for i, condition := range conditions {
		if condition == "" {
			return errfmt.Errorf("%s: condition %d is empty", filePath, i)
		}

		// Try to compile the condition
		_, err := CompileCondition(env, condition)
		if err != nil {
			return fmt.Errorf("%s: condition %d (%s) is invalid: %w", filePath, i, condition, err)
		}
	}

	return nil
}
