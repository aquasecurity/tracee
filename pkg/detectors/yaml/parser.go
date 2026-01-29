package yaml

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/errfmt"
)

const (
	// MaxYAMLFileSize is the maximum allowed size for a YAML detector file (1 MB)
	// This prevents memory exhaustion attacks via extremely large YAML files
	MaxYAMLFileSize = 1 * 1024 * 1024 // 1 MB
)

// ParseFile reads and parses a detector file (supports both plain and CRD formats)
// Both formats normalize to YAMLDetectorSpec
func ParseFile(filePath string) (*YAMLDetectorSpec, error) {
	data, err := readFileData(filePath)
	if err != nil {
		return nil, err
	}

	// Detect format from data
	isJSON := strings.HasSuffix(filePath, ".json")
	format, err := peekDetectorFormat(data, isJSON)
	if err != nil {
		return nil, err
	}

	// Route to appropriate parser based on detected format
	switch format {
	case FormatPlainYAML:
		var spec YAMLDetectorSpec
		if isJSON {
			err = json.Unmarshal(data, &spec)
		} else {
			err = yaml.Unmarshal(data, &spec)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse plain detector: %w", err)
		}
		return &spec, nil

	case FormatK8sCRD:
		// Parse CRD format and extract Spec
		file, parseErr := ParseCRDFile(filePath)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse CRD detector: %w", parseErr)
		}
		// Extract Spec from CRD format and convert to YAMLDetectorSpec
		return GetDetectorSpecFromCRD(file), nil

	default:
		return nil, errfmt.Errorf("unsupported detector format: %s", format)
	}
}

// ToDetectorDefinition converts a YAML spec to a DetectorDefinition
func ToDetectorDefinition(spec *YAMLDetectorSpec) (*detection.DetectorDefinition, error) {
	// Parse version for produced event
	version, err := parseVersion(spec.ProducedEvent.Version)
	if err != nil {
		return nil, fmt.Errorf("invalid version '%s': %w", spec.ProducedEvent.Version, err)
	}

	// Parse event fields if present
	var eventFields []*v1beta1.EventField
	if len(spec.ProducedEvent.Fields) > 0 {
		eventFields = make([]*v1beta1.EventField, 0, len(spec.ProducedEvent.Fields))
		for _, f := range spec.ProducedEvent.Fields {
			eventFields = append(eventFields, &v1beta1.EventField{
				Name: f.Name,
				Type: f.Type,
			})
		}
	}

	// Parse requirements
	requirements, err := parseRequirements(spec.Requirements)
	if err != nil {
		return nil, fmt.Errorf("failed to parse requirements: %w", err)
	}

	// Parse threat metadata (optional)
	var threat *v1beta1.Threat
	if spec.Threat != nil {
		threat, err = parseThreat(spec.Threat)
		if err != nil {
			return nil, fmt.Errorf("failed to parse threat: %w", err)
		}
	}

	// Construct definition with EventDefinition inline to avoid copying protobuf structs
	def := &detection.DetectorDefinition{
		ID: spec.ID,
		ProducedEvent: v1beta1.EventDefinition{
			Name:        spec.ProducedEvent.Name,
			Version:     version,
			Description: spec.ProducedEvent.Description,
			Tags:        spec.ProducedEvent.Tags,
			Fields:      eventFields,
		},
		Requirements:   requirements,
		ThreatMetadata: threat,
		AutoPopulate: detection.AutoPopulateFields{
			Threat:          spec.AutoPopulate.Threat,
			DetectedFrom:    spec.AutoPopulate.DetectedFrom,
			ProcessAncestry: spec.AutoPopulate.ProcessAncestry,
		},
	}

	return def, nil
}

// parseProducedEvent converts ProducedEventSpec to EventDefinition
func parseProducedEvent(spec ProducedEventSpec) (*v1beta1.EventDefinition, error) {
	version, err := parseVersion(spec.Version)
	if err != nil {
		return nil, fmt.Errorf("invalid version '%s': %w", spec.Version, err)
	}

	eventDef := &v1beta1.EventDefinition{
		Name:        spec.Name,
		Version:     version,
		Description: spec.Description,
		Tags:        spec.Tags,
	}

	// Parse event fields if present
	if len(spec.Fields) > 0 {
		fields := make([]*v1beta1.EventField, 0, len(spec.Fields))
		for _, f := range spec.Fields {
			fields = append(fields, &v1beta1.EventField{
				Name: f.Name,
				Type: f.Type,
			})
		}
		eventDef.Fields = fields
	}

	return eventDef, nil
}

// parseRequirements converts RequirementsSpec to DetectorRequirements
func parseRequirements(spec RequirementsSpec) (detection.DetectorRequirements, error) {
	req := detection.DetectorRequirements{
		Architectures: spec.Architectures,
	}

	// Parse version constraints
	if spec.MinTraceeVersion != "" {
		minVer, err := parseVersion(spec.MinTraceeVersion)
		if err != nil {
			return req, fmt.Errorf("invalid min_tracee_version '%s': %w", spec.MinTraceeVersion, err)
		}
		req.MinTraceeVersion = minVer
	}

	if spec.MaxTraceeVersion != "" {
		maxVer, err := parseVersion(spec.MaxTraceeVersion)
		if err != nil {
			return req, fmt.Errorf("invalid max_tracee_version '%s': %w", spec.MaxTraceeVersion, err)
		}
		req.MaxTraceeVersion = maxVer
	}

	// Parse event requirements
	if len(spec.Events) > 0 {
		events := make([]detection.EventRequirement, 0, len(spec.Events))
		for _, e := range spec.Events {
			eventReq, err := parseEventRequirement(e)
			if err != nil {
				return req, fmt.Errorf("failed to parse event requirement '%s': %w", e.Name, err)
			}
			events = append(events, eventReq)
		}
		req.Events = events
	}

	// Parse enrichment requirements
	if len(spec.Enrichments) > 0 {
		enrichments := make([]detection.EnrichmentRequirement, 0, len(spec.Enrichments))
		for _, e := range spec.Enrichments {
			enrichReq, err := parseEnrichmentRequirement(e)
			if err != nil {
				return req, fmt.Errorf("failed to parse enrichment requirement '%s': %w", e.Name, err)
			}
			enrichments = append(enrichments, enrichReq)
		}
		req.Enrichments = enrichments
	}

	return req, nil
}

// parseEventRequirement converts EventRequirementSpec to EventRequirement
func parseEventRequirement(spec EventRequirementSpec) (detection.EventRequirement, error) {
	req := detection.EventRequirement{
		Name:         spec.Name,
		DataFilters:  spec.DataFilters,
		ScopeFilters: spec.ScopeFilters,
	}

	// Parse dependency type
	if spec.Dependency != "" {
		dep, err := parseDependencyType(spec.Dependency)
		if err != nil {
			return req, err
		}
		req.Dependency = dep
	}
	// Zero value is DependencyRequired (default)

	// Parse version constraints
	if spec.MinVersion != "" {
		minVer, err := parseVersion(spec.MinVersion)
		if err != nil {
			return req, fmt.Errorf("invalid min_version '%s': %w", spec.MinVersion, err)
		}
		req.MinVersion = minVer
	}

	if spec.MaxVersion != "" {
		maxVer, err := parseVersion(spec.MaxVersion)
		if err != nil {
			return req, fmt.Errorf("invalid max_version '%s': %w", spec.MaxVersion, err)
		}
		req.MaxVersion = maxVer
	}

	return req, nil
}

// parseEnrichmentRequirement converts EnrichmentRequirementSpec to EnrichmentRequirement
func parseEnrichmentRequirement(spec EnrichmentRequirementSpec) (detection.EnrichmentRequirement, error) {
	req := detection.EnrichmentRequirement{
		Name:   spec.Name,
		Config: spec.Config,
	}

	// Parse dependency type
	if spec.Dependency != "" {
		dep, err := parseDependencyType(spec.Dependency)
		if err != nil {
			return req, err
		}
		req.Dependency = dep
	}
	// Zero value is DependencyRequired (default)

	return req, nil
}

// parseThreat converts ThreatSpec to v1beta1.Threat
func parseThreat(spec *ThreatSpec) (*v1beta1.Threat, error) {
	severity, err := parseSeverity(spec.Severity)
	if err != nil {
		return nil, err
	}

	threat := &v1beta1.Threat{
		Name:        spec.Name,
		Description: spec.Description,
		Severity:    severity,
		Properties:  spec.Properties,
	}

	// Parse MITRE mapping if present
	if spec.Mitre != nil {
		mitre := &v1beta1.Mitre{}

		if spec.Mitre.Tactic != nil {
			mitre.Tactic = &v1beta1.MitreTactic{
				Name: spec.Mitre.Tactic.Name,
			}
		}

		if spec.Mitre.Technique != nil {
			mitre.Technique = &v1beta1.MitreTechnique{
				Id:   spec.Mitre.Technique.ID,
				Name: spec.Mitre.Technique.Name,
			}
		}

		threat.Mitre = mitre
	}

	return threat, nil
}

// parseVersion parses a semantic version string (e.g., "1.0.0") to v1beta1.Version
func parseVersion(version string) (*v1beta1.Version, error) {
	if version == "" {
		return nil, errfmt.Errorf("version cannot be empty")
	}

	parts := strings.Split(version, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, errfmt.Errorf("version must be in format 'major.minor' or 'major.minor.patch'")
	}

	major, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %w", err)
	}

	minor, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid minor version: %w", err)
	}

	ver := &v1beta1.Version{
		Major: uint64(major),
		Minor: uint64(minor),
	}

	if len(parts) == 3 {
		patch, err := strconv.ParseUint(parts[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid patch version: %w", err)
		}
		ver.Patch = uint64(patch)
	}

	return ver, nil
}

// parseDependencyType converts a string to DependencyType
func parseDependencyType(dep string) (detection.DependencyType, error) {
	switch strings.ToLower(dep) {
	case "required":
		return detection.DependencyRequired, nil
	case "optional":
		return detection.DependencyOptional, nil
	default:
		return detection.DependencyRequired, errfmt.Errorf("invalid dependency type '%s': must be 'required' or 'optional'", dep)
	}
}

// parseSeverity converts a severity string to protobuf enum value
func parseSeverity(severity string) (v1beta1.Severity, error) {
	switch strings.ToLower(severity) {
	case "low":
		return v1beta1.Severity_LOW, nil
	case "medium":
		return v1beta1.Severity_MEDIUM, nil
	case "high":
		return v1beta1.Severity_HIGH, nil
	case "critical":
		return v1beta1.Severity_CRITICAL, nil
	default:
		return v1beta1.Severity_INFO, errfmt.Errorf("invalid severity '%s': must be 'low', 'medium', 'high', or 'critical'", severity)
	}
}

// ParseAndConvert is a convenience function that parses a file and converts it to DetectorDefinition
func ParseAndConvert(filePath string) (*detection.DetectorDefinition, *YAMLDetectorSpec, error) {
	spec, err := ParseFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse file: %w", err)
	}

	def, err := ToDetectorDefinition(spec)
	if err != nil {
		return nil, spec, fmt.Errorf("failed to convert to detector definition: %w", err)
	}

	return def, spec, nil
}
