package events

import (
	"fmt"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

// LEGACY: These functions are used for converting threat metadata from the old signature system.
// They will be removed once the new EventDetector framework replaces the legacy signature system.
// Do not add new functionality here.

// getThreat converts metadata to Threat protobuf message
// Used by legacy signature system to convert trace.Metadata to protobuf Threat
func getThreat(description string, metadata map[string]interface{}) *pb.Threat {
	if metadata == nil {
		return nil
	}
	// if metadata doesn't contain severity, it's not a threat,
	// severity is set when we have an event created from a signature
	_, ok := metadata["Severity"]
	if !ok {
		return nil
	}

	var (
		mitreTactic        string
		mitreTechniqueId   string
		mitreTechniqueName string
		name               string
	)

	if _, ok := metadata["Category"]; ok {
		if val, ok := metadata["Category"].(string); ok {
			mitreTactic = val
		}
	}

	if _, ok := metadata["external_id"]; ok {
		if val, ok := metadata["external_id"].(string); ok {
			mitreTechniqueId = val
		}
	}

	if _, ok := metadata["Technique"]; ok {
		if val, ok := metadata["Technique"].(string); ok {
			mitreTechniqueName = val
		}
	}

	if _, ok := metadata["signatureName"]; ok {
		if val, ok := metadata["signatureName"].(string); ok {
			name = val
		}
	}

	properties := make(map[string]string)

	for k, v := range metadata {
		if k == "Category" ||
			k == "external_id" ||
			k == "Technique" ||
			k == "Severity" ||
			k == "signatureName" {
			continue
		}

		properties[k] = sanitizeStringForProtobuf(fmt.Sprint(v))
	}

	return &pb.Threat{
		Description: sanitizeStringForProtobuf(description),
		Mitre: &pb.Mitre{
			Tactic: &pb.MitreTactic{
				Name: mitreTactic,
			},
			Technique: &pb.MitreTechnique{
				Id:   mitreTechniqueId,
				Name: sanitizeStringForProtobuf(mitreTechniqueName),
			},
		},
		Severity:   getSeverity(metadata),
		Name:       sanitizeStringForProtobuf(name),
		Properties: properties,
	}
}

// getSeverity extracts severity from metadata
// Used by legacy signature system to convert severity integer to protobuf Severity enum
func getSeverity(metadata map[string]interface{}) pb.Severity {
	severityValue, ok := metadata["Severity"].(int)
	if ok {
		switch severityValue {
		case 0:
			return pb.Severity_INFO
		case 1:
			return pb.Severity_LOW
		case 2:
			return pb.Severity_MEDIUM
		case 3:
			return pb.Severity_HIGH
		case 4:
			return pb.Severity_CRITICAL
		}
	}

	return pb.Severity_INFO
}
