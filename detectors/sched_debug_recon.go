package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&SchedDebugRecon{})
}

// SchedDebugRecon detects when the sched_debug file is read from a container.
// This file contains CPU and process information that adversaries may gather for reconnaissance.
type SchedDebugRecon struct {
	logger          detection.Logger
	schedDebugPaths map[string]bool
}

func (d *SchedDebugRecon) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1029",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_file_open",
					Dependency: detection.DependencyRequired,
					// CRITICAL: Use container=started to match old Origin: "container" behavior
					ScopeFilters: []string{"container=started"},
					// DataFilters could be added here for pathname, but we check multiple paths
					// and need to verify it's a read operation, so logic is in OnEvent
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "sched_debug_recon",
			Description: "sched_debug CPU file was read",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "sched_debug CPU file was read",
			Description: "The sched_debug file was read. This file contains information about your CPU and processes. Adversaries may read this file in order to gather that information for their use.",
			Severity:    v1beta1.Severity_LOW,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Discovery",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1613",
					Name: "Container and Resource Discovery",
				},
			},
			Properties: map[string]string{
				"Category": "discovery",
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *SchedDebugRecon) Init(params detection.DetectorParams) error {
	d.logger = params.Logger

	// Initialize sched_debug paths set
	d.schedDebugPaths = map[string]bool{
		"/proc/sched_debug":             true,
		"/sys/kernel/debug/sched/debug": true,
	}

	d.logger.Debugw("SchedDebugRecon detector initialized")
	return nil
}

func (d *SchedDebugRecon) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract pathname
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		d.logger.Debugw("Failed to extract pathname", "error", err)
		return nil, nil
	}

	// Check if path is one of the sched_debug files
	if !d.schedDebugPaths[pathname] {
		return nil, nil
	}

	// Extract flags
	flags, err := v1beta1.GetDataSafe[int32](event, "flags")
	if err != nil {
		d.logger.Debugw("Failed to extract flags", "error", err)
		return nil, nil
	}

	// Check if it's a read operation
	if !parsers.IsFileRead(int(flags)) {
		return nil, nil
	}

	// Detection: sched_debug file read from container
	d.logger.Debugw("sched_debug file read detected",
		"path", pathname,
		"container", v1beta1.GetContainerID(event))

	return detection.Detected(), nil
}

func (d *SchedDebugRecon) Close() error {
	d.logger.Debugw("SchedDebugRecon detector closed")
	return nil
}
