package detectors

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&ProcKcoreRead{})
}

// ProcKcoreRead detects attempts to read /proc/kcore from containers.
// /proc/kcore provides a full memory dump and can be used for container escape.
type ProcKcoreRead struct {
	logger detection.Logger
}

func (d *ProcKcoreRead) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1021",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_file_open",
					Dependency: detection.DependencyRequired,
					// Use suffix match to handle edge cases (symlinks, etc.)
					// Original signature uses strings.HasSuffix
					DataFilters: []string{
						"pathname=/proc/kcore",
					},
					// Scope filter: only from containers (matching original "Origin: container")
					ScopeFilters: []string{
						"container=started",
					},
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "proc_kcore_read",
			Description: "Attempt to read /proc/kcore memory file detected",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Kcore memory file read",
			Description: "An attempt to read /proc/kcore file was detected. KCore provides a full dump of the physical memory of the system in the core file format. Adversaries may read this file to get all of the host memory and use this information for container escape.",
			Severity:    v1beta1.Severity_MEDIUM,
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

func (d *ProcKcoreRead) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("ProcKcoreRead detector initialized")
	return nil
}

func (d *ProcKcoreRead) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// DataFilter ensures pathname suffix matches, ScopeFilter ensures container origin
	// Still need to check if this is a read operation and verify suffix match for edge cases

	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		return nil, nil
	}

	flags, err := v1beta1.GetDataSafe[int64](event, "flags")
	if err != nil {
		return nil, nil
	}

	// Verify suffix match (matching original signature logic)
	if strings.HasSuffix(pathname, "/proc/kcore") && parsers.IsFileRead(int(flags)) {
		return []detection.DetectorOutput{{Data: nil}}, nil
	}

	return nil, nil
}

func (d *ProcKcoreRead) Close() error {
	d.logger.Debugw("ProcKcoreRead detector closed")
	return nil
}
