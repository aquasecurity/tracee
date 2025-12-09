package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&CorePatternModification{})
}

// CorePatternModification detects modifications to the core_pattern file from containers.
// This can be exploited for container escape through the kernel core_pattern feature.
type CorePatternModification struct {
	logger detection.Logger
}

func (d *CorePatternModification) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1011",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:         "security_file_open",
					Dependency:   detection.DependencyRequired,
					ScopeFilters: []string{"container=started"},
					DataFilters:  []string{"pathname=*/proc/sys/kernel/core_pattern"},
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "core_pattern_modification",
			Description: "Core dumps configuration file modification detected",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Core dumps configuration file modification detected",
			Description: "Modification of the core dump configuration file (core_pattern) detected. Core dumps are usually written to disk when a program crashes. Certain modifications enable container escaping through the kernel core_pattern feature.",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Privilege Escalation",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1611",
					Name: "Escape to Host",
				},
			},
			Properties: map[string]string{
				"Category": "privilege-escalation",
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *CorePatternModification) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("CorePatternModification detector initialized")
	return nil
}

func (d *CorePatternModification) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// DataFilter ensures pathname suffix matches, ScopeFilter ensures container origin
	// Only need to check if this is a write operation

	flags, err := v1beta1.GetDataSafe[int32](event, "flags")
	if err != nil {
		return nil, nil
	}

	if parsers.IsFileWrite(int(flags)) {
		return detection.Detected(), nil
	}

	return nil, nil
}

func (d *CorePatternModification) Close() error {
	d.logger.Debugw("CorePatternModification detector closed")
	return nil
}
