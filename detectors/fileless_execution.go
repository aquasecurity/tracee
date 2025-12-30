package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&FilelessExecution{})
}

// FilelessExecution detects execution of code from memory (memfd, anon_inode) rather than files.
// Adversaries use fileless execution to avoid writing malicious code to disk.
type FilelessExecution struct {
	logger detection.Logger
}

func (d *FilelessExecution) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-105",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "sched_process_exec",
					Dependency: detection.DependencyRequired,
					// We can't use DataFilters here because we need to check if pathname
					// is a memory path using parsers.IsMemoryPath(), which requires custom logic
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "fileless_execution",
			Description: "Fileless execution detected",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Fileless execution detected",
			Description: "Fileless execution was detected. Executing a process from memory instead from a file in the filesystem may indicate that an adversary is trying to avoid execution detection.",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Defense Evasion",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1620",
					Name: "Reflective Code Loading",
				},
			},
			Properties: map[string]string{
				"Category": "defense-evasion",
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *FilelessExecution) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("FilelessExecution detector initialized")
	return nil
}

func (d *FilelessExecution) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract pathname from sched_process_exec event
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		d.logger.Debugw("Failed to extract pathname", "error", err)
		return nil, nil
	}

	// Check if the path is a memory path (e.g., /memfd:, /dev/shm/, anonymous inode)
	if !parsers.IsMemoryPath(pathname) {
		return nil, nil
	}

	// Detection: process executed from memory
	d.logger.Debugw("Fileless execution detected", "pathname", pathname)
	return []detection.DetectorOutput{{Data: nil}}, nil
}

func (d *FilelessExecution) Close() error {
	d.logger.Debugw("FilelessExecution detector closed")
	return nil
}
