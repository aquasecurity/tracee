package detectors

import (
	"context"
	"strings"

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
	logger      detection.Logger
	corePattern string
}

func (d *CorePatternModification) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1011",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_file_open",
					Dependency: detection.DependencyRequired,
					// CRITICAL: Use container=started to match old Origin: "container" behavior
					ScopeFilters: []string{"container=started"},
					// DataFilter for pathname would be ideal, but we use HasSuffix logic
					// Could use: DataFilters: []string{"pathname=/proc/sys/kernel/core_pattern"}
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
	d.corePattern = "/proc/sys/kernel/core_pattern"
	d.logger.Debugw("CorePatternModification detector initialized")
	return nil
}

func (d *CorePatternModification) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract pathname
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		d.logger.Debugw("Failed to extract pathname", "error", err)
		return nil, nil
	}

	// Check if path is core_pattern (using HasSuffix for flexibility)
	if !strings.HasSuffix(pathname, d.corePattern) {
		return nil, nil
	}

	// Extract flags
	flags, err := v1beta1.GetDataSafe[int32](event, "flags")
	if err != nil {
		d.logger.Debugw("Failed to extract flags", "error", err)
		return nil, nil
	}

	// Check if it's a write operation
	if !parsers.IsFileWrite(int(flags)) {
		return nil, nil
	}

	// Detection: core_pattern modification from container
	d.logger.Debugw("core_pattern modification detected",
		"path", pathname,
		"container", v1beta1.GetContainerID(event))

	return []detection.DetectorOutput{{Data: nil}}, nil
}

func (d *CorePatternModification) Close() error {
	d.logger.Debugw("CorePatternModification detector closed")
	return nil
}
